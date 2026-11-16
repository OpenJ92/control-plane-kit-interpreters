"""Read-only physical evidence for one owner-prepared PostgreSQL check.

No image acquisition, container exec, helper container, mutation or SQL probe.
Private bytes are consumed only by the existing recipient-file verifier.
"""
from control_plane_kit_core.products import ProductReference
from control_plane_kit_core.receiver_configuration import select_receiver_node_control_configuration_artifact
from .configuration import configuration_volume_name, installed_configuration_matches, _container_incarnation_fingerprint
from .postgres_recipient import observe_postgres_recipient_route
from .sdk import DockerSdkConfigurationMount, DockerSdkSecretMount, matches_image_reference


def observe_postgres_readiness_recipient(client, prepared, secrets, *, deadline, clock, check_window):
    # Runtime imports are local: runtime composes this effect, while these pure
    # naming/ownership functions remain the one source for its resource names.
    from .runtime import (_container_name, _network_name, _node_labels, _runtime_labels,
        _require_runtime_owner, _secret_volume_name, _volume_name, _LABEL_PREFIX, _NODE_MATERIAL_PROFILE)

    def require(condition):
        if condition is not True:
            raise ValueError

    def read(action):
        check_window()
        value = action()
        check_window()
        return value

    binding = prepared.binding
    install, wait = binding.installation, binding.wait
    material, = install.products
    product = material.product
    pg = read(lambda: client.inspect_container(_container_name(install, material.node_id)))
    expected = _node_labels(install, material)
    require(pg is not None and all(pg.labels.get(key) == value for key, value in expected.items()))
    require(_container_incarnation_fingerprint(pg.container_id) == binding.receipt.current_realization_fingerprint)

    def image_for(container, product):
        reference = product.image.execution_reference
        image = read(lambda: client.inspect_image(reference))
        require(image is not None and matches_image_reference(reference, image.repo_digests)
            and container.running is True and container.started_at is not None
            and container.image_id == image.image_id and container.configured_user == image.configured_user)
        return image

    image = image_for(pg, product)
    uid = image.secret_file_owner_uid()
    file, = secrets.files
    mount = DockerSdkSecretMount(file.target_path,
        _secret_volume_name(install, material.node_id, file, owner_uid=uid))
    environment = {value.name: value.value for value in material.public_environment + material.socket_environment}
    for key, value in secrets.environment.items():
        require(key not in environment or environment[key] == value)
        environment[key] = value
    read(lambda: client.verify_secret_recipient(pg.container_id, expected_environment=environment,
        mounts=(mount,), expected_files=secrets.files, admitted_image=image, owner_uid=uid))

    contract = product.runtime_contract
    artifact = select_receiver_node_control_configuration_artifact(artifacts=contract.configuration_artifacts,
        environment=material.public_environment + material.socket_environment, control_surfaces=contract.control_surfaces)
    if install.configuration_instances is None:
        volume = _volume_name(install, material.node_id, artifact.artifact_id)
    else:
        allocation, = (value for value in install.configuration_instances.instances
            if value.artifact_id == artifact.artifact_id and value.content_digest == artifact.content_digest
            and value.target_path == artifact.target_path)
        volume = configuration_volume_name(allocation)
    read(lambda: installed_configuration_matches(client, pg.container_id,
        (DockerSdkConfigurationMount(artifact, volume),)))

    gateway_target = prepared.signing_context.gateway_target
    gateway = read(lambda: client.inspect_container(_container_name(wait, gateway_target.node_id.value)))
    gateway_product = prepared.gateway_product.product
    reference = ProductReference.from_document(prepared.gateway_product)
    known = dict(kind="container", workspace=wait.source.workspace_id, runtime=material.runtime_id,
        node=gateway_target.node_id.value, plan=wait.source.plan_id, **{
            "desired-graph": wait.source.desired_graph_id, "product": reference.identity.key,
            "descriptor": reference.descriptor_sha256.value, "image": gateway_product.image.digest,
            "material-profile": _NODE_MATERIAL_PROFILE})
    require(gateway is not None and all(gateway.labels.get(f"{_LABEL_PREFIX}.{key}") == value
        for key, value in known.items()))
    image_for(gateway, gateway_product)
    for artifact in (prepared.gateway_route_artifact, prepared.gateway_transit_artifact):
        mounted, = (value for value in gateway.readonly_secret_mounts if value.target_path == artifact.target_path)
        read(lambda: installed_configuration_matches(client, gateway.container_id,
            (DockerSdkConfigurationMount(artifact, mounted.volume_name),)))

    network_name = _network_name(wait, material.runtime_id)
    network = read(lambda: client.inspect_network(network_name))
    require(network is not None)
    _require_runtime_owner(network.labels, _runtime_labels(wait, material.runtime_id), "network")
    return observe_postgres_recipient_route(client, network_name=network_name, network_id=network.network_id,
        gateway_id=gateway.container_id, recipient_id=pg.container_id, route=prepared.route,
        deadline=deadline, clock=clock)
