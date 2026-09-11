"""Opt-in provider contract fixture; contains no production runtime behavior."""

from __future__ import annotations


class ProviderContractObservation:
    """Transparent recipient-call observation and a fixture-only pull ceiling."""

    def __init__(self, sdk, recipient_name, record=None):
        self.sdk = sdk
        self.recipient_name = recipient_name
        self.record = record
        self._active = False
        self._recipient_id = None
        self._available = True
        self._pull_attempted = False
        self._stages = {
            "create": {"method": "POST", "outcome": "not-reached", "status": None},
            "inspect": {"method": "GET", "outcome": "not-reached", "status": None},
        }

    def __enter__(self):
        api = self.sdk._client().api
        self._api = api
        self._originals = (self.sdk.create_container, self.sdk.pull_image,
                           api.create_container, api.inspect_container)
        original_recipient, _, original_create, original_inspect = self._originals

        def recipient(*args, **kwargs):
            if kwargs.get("name") != self.recipient_name:
                return original_recipient(*args, **kwargs)
            self._active = True
            try:
                return original_recipient(*args, **kwargs)
            finally:
                self._active = False

        def create(*args, **kwargs):
            if not self._active or kwargs.get("name") != self.recipient_name:
                return original_create(*args, **kwargs)
            result = self._call("create", original_create, args, kwargs)
            try:
                identity = result.get("Id") if isinstance(result, dict) else None
                if isinstance(identity, str) and identity:
                    self._recipient_id = identity
                else:
                    self._available = False
            except Exception:
                self._available = False
            return result

        def inspect(*args, **kwargs):
            identity = args[0] if args else kwargs.get("container")
            if (not self._active or self._recipient_id is None
                    or identity != self._recipient_id):
                return original_inspect(*args, **kwargs)
            return self._call("inspect", original_inspect, args, kwargs)

        def prohibit_pull(*args, **kwargs):
            self._pull_attempted = True
            self._emit()
            raise RuntimeError("fixture image pull prohibited")

        self.sdk.create_container = recipient
        self.sdk.pull_image = prohibit_pull
        api.create_container = create
        api.inspect_container = inspect
        return self

    def _call(self, stage, original, args, kwargs):
        if self._stages[stage]["outcome"] != "not-reached":
            self._available = False
        try:
            result = original(*args, **kwargs)
        except Exception as error:
            self._stages[stage]["outcome"] = "raised"
            try:
                from docker.errors import APIError
                if isinstance(error, APIError):
                    response = error.response
                    status = None if response is None else response.status_code
                    if type(status) is int and 100 <= status <= 599:
                        self._stages[stage]["status"] = status
            except Exception:
                self._available = False
            self._emit()
            raise
        self._stages[stage]["outcome"] = "returned"
        self._emit()
        return result

    def _emit(self):
        if self.record is not None:
            try:
                self.record(self.report())
            except Exception:
                self._available = False

    def __exit__(self, exc_type, exc, traceback):
        (self.sdk.create_container, self.sdk.pull_image,
         self._api.create_container, self._api.inspect_container) = self._originals
        self._active = False
        return False

    def report(self):
        return {"create": dict(self._stages["create"]),
                "inspect": dict(self._stages["inspect"]),
                "diagnostic_available": self._available,
                "pull_attempted": self._pull_attempted}

# Published ABI specimens are pinned fixture data, not production descriptors.
IMAGE_REFERENCE = (
    "ghcr.io/openj92/control-plane-kit-servers/secrets-server@"
    "sha256:41aba38eb255779c8a0230724d9cc4fffd1dc5d5dfbfafdc133f1629139edfe7"
)
PRODUCT_DOCUMENT_SHA256 = "1087194150df37d2bb597c1644cfd30232a2d7d2e57fbb1c209115722ecc1df8"
BOOTSTRAP_CONTRACT_SHA256 = "9a058b056659e40742b8dd91162bf63c3075abf9f7317a84e1aec1f7a1360a77"
SPECIMEN_SOURCE = "OpenJ92/control-plane-kit-servers@80c3ffd34b157940ec72cfc22156a27dcaa1fc5c/products/secrets_server"


def prepare_fixture(run_id):
    """Build real runtime values from wholly new in-controller dummy inputs."""
    import base64
    from dataclasses import replace
    import hashlib
    import json
    import os
    import re
    import secrets
    from types import SimpleNamespace

    from control_plane_kit_core.environment import PublicStaticEnvironmentBinding
    from control_plane_kit_core.operations.run_identity import RunId
    from control_plane_kit_core.planning import ActivityId, NodeTarget, RuntimeTarget, StartNode, StartRuntime
    from control_plane_kit_core.products import ProductDescriptorCodec, ProductDescriptorDigest, ProductIdentity, ProductReference
    from control_plane_kit_core.runtime_effects import RuntimeEffectKind, RuntimeEffectRequest, RuntimeEffectSource, RuntimeProductMaterial
    from control_plane_kit_core.secrets import (SecretFileDelivery, SecretFileMode, SecretFilePathBinding,
        SecretProviderEndpointReference, SecretReference, SecretResolutionGrant, SecretResolved,
        SecretMissing, SecretUseIntent, SecretValue)
    from control_plane_kit_core.types import RuntimeKind
    from control_plane_kit_interpreters.docker.runtime import (
        _container_name, _digest, _network_name, _node_labels, _runtime_labels, _volume_name)

    if not re.fullmatch(r"cpk141-[a-z0-9-]{4,48}", run_id):
        raise RuntimeError("fixture identity invalid")
    if (hashlib.sha256(PUBLISHED_PRODUCT_DOCUMENT).hexdigest() != PRODUCT_DOCUMENT_SHA256
            or hashlib.sha256(PUBLISHED_BOOTSTRAP_CONTRACT).hexdigest() != BOOTSTRAP_CONTRACT_SHA256):
        raise RuntimeError("fixture ABI specimen mismatch")
    original = ProductDescriptorCodec().decode_document(PUBLISHED_PRODUCT_DOCUMENT).product
    abi = json.loads(PUBLISHED_BOOTSTRAP_CONTRACT)
    if original.image.execution_reference != IMAGE_REFERENCE or abi["schema"] != "cpk-secrets.bootstrap-contract":
        raise RuntimeError("fixture image ABI mismatch")
    workspace = run_id + "-workspace"
    node_id, runtime_id = run_id + "-secrets", run_id + "-runtime"
    root_key = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    document = json.dumps([{"subject": "fixture-metadata-only", "token": secrets.token_urlsafe(48),
        "grants": [{"action": "secret.metadata", "workspace_id": workspace}]}], separators=(",", ":"))
    targets = ("/run/secrets/cpk-secrets/master.key", "/run/secrets/cpk-secrets/credentials.json")
    intents = (SecretUseIntent.SECRETS_CUSTODY_ROOT_KEY, SecretUseIntent.SECRETS_PROVIDER_CREDENTIALS_DOCUMENT)
    env_names = ("CPK_SECRETS_MASTER_KEY_FILE", "CPK_SECRETS_CREDENTIALS_FILE")
    references = tuple(SecretReference("secret://fixture/" + run_id + "/" + suffix)
                       for suffix in ("root-key", "credential-document"))
    raw_values = (root_key, document)
    caps = {entry["default_target"]: entry["maximum_bytes"] for entry in abi["bootstrap_files"]}
    if any(len(value.encode()) > caps[target] for target, value in zip(targets, raw_values)):
        raise RuntimeError("fixture input bound exceeded")
    deliveries = tuple(SecretFileDelivery(target, ref, intent, SecretFileMode.OWNER_READ_ONLY,
                       SecretFilePathBinding(env)) for target,ref,intent,env in zip(targets,references,intents,env_names))
    contract = replace(original.runtime_contract, secret_deliveries=deliveries,
        public_environment=(PublicStaticEnvironmentBinding("CPK_SECRETS_DATABASE_PATH", "/var/lib/cpk-secrets/secrets.sqlite3"),
                            PublicStaticEnvironmentBinding("CPK_SECRETS_PROVIDER_ID", run_id)))
    product = replace(original, identity=ProductIdentity("control-plane-kit-test", "start-node-provider-contract", 1),
                      runtime_contract=contract)
    content = ProductDescriptorCodec().encode_document(product)
    material = RuntimeProductMaterial(node_id=node_id, runtime_id=runtime_id,
        reference=ProductReference(product.identity, ProductDescriptorDigest(content.content_digest)),
        product=product, public_environment=contract.public_environment)

    def request(operation, suffix, grants=()):
        return RuntimeEffectRequest(effect_id=run_id + "-" + suffix + "-effect",
            kind=RuntimeEffectKind.REALIZE_ACTIVITY, runtime_kind=RuntimeKind.DOCKER,
            source=RuntimeEffectSource(workspace_id=workspace, request_id=run_id + "-" + suffix + "-request",
                run_id=RunId(run_id + "-run"), plan_id=run_id + "-plan", base_graph_id=run_id + "-base",
                desired_graph_id=run_id + "-desired", intent_event_id=run_id + "-" + suffix + "-effect"),
            activity_id=ActivityId(run_id + "-" + suffix + "-activity"), operation=operation,
            products=() if suffix == "runtime" else (material,), secret_resolution_grants=grants)

    grants = tuple(SecretResolutionGrant(authorization_id="suse_" + _digest(run_id, str(i)),
        workspace_id=workspace, reference_registration_id="sref_" + _digest(run_id, "ref", str(i)),
        provider_registration_id="sprov_" + _digest(run_id, "provider"),
        endpoint_reference=SecretProviderEndpointReference(run_id + "-in-memory"),
        credential_reference=SecretReference("secret://fixture/" + run_id + "/unused-provider-credential"),
        reference=ref, intent=intent, actor_subject="fixture", correlation_id=run_id + "-resolution",
        intent_fingerprint=_digest(run_id, "intent", str(i)), run_id=run_id + "-run",
        activity_id=run_id + "-node-activity", effect_id=run_id + "-node-effect")
        for i,(ref,intent) in enumerate(zip(references,intents)))
    start = request(StartRuntime(RuntimeTarget(runtime_id)), "runtime")
    node = request(StartNode(NodeTarget(node_id)), "node", grants)
    node_labels = _node_labels(node, material)
    network = _network_name(node, runtime_id)
    recipient = _container_name(node, node_id)
    data_volume = _volume_name(node, node_id, "provider-data")
    secret_volumes = tuple(_volume_name(node, node_id, "secret-" + _digest(target, ref.reference_id)[:16])
                           for target,ref in zip(targets,references))
    volume_labels = {data_volume: {**node_labels, "org.openj92.cpk.volume.kind": "retained-data"}}
    for name,target,ref in zip(secret_volumes,targets,references):
        volume_labels[name] = {**node_labels, "org.openj92.cpk.volume.kind": "secret-file",
                              "org.openj92.cpk.secret.target": target, "org.openj92.cpk.secret.reference": ref.reference_id}

    class Resolver:
        def resolve(self, grant):
            if grant not in grants:
                return SecretMissing(grant.reference)
            return SecretResolved(grant.reference, SecretValue(raw_values[grants.index(grant)]))

    return SimpleNamespace(start=start, node=node, material=material, resolver=Resolver(), grants=grants,
        network=network, recipient=recipient, node_labels=node_labels,
        network_labels=_runtime_labels(start, runtime_id), volume_labels=volume_labels,
        secret_volumes=secret_volumes, data_volume=data_volume, targets=targets,
        digests=tuple(hashlib.sha256(value.encode()).hexdigest() for value in raw_values))

PUBLISHED_PRODUCT_DOCUMENT = b'{"schema":"control-plane-kit.product","product":{"kind":"container-server","identity":{"namespace":"control-plane-kit","name":"secrets-server","contract_revision":1},"image":{"registry":"ghcr.io","repository":"openj92/control-plane-kit-servers/secrets-server","digest":"sha256:41aba38eb255779c8a0230724d9cc4fffd1dc5d5dfbfafdc133f1629139edfe7","tag":"bootstrap-158-4468cd0","platforms":[],"provenance":{"dockerfile":"products/secrets_server/Dockerfile","publish":"ghcr","source-commit":"68d0da6aed3a383d6bdc284cf4a6a6063a31487e","source-repository":"OpenJ92/control-plane-kit-secrets"}},"runtime_contract":{"sockets":{"requirements":{},"providers":{"control":{"protocol":{"transport":"tcp","application":"http"}}}},"provider_ports":[{"provider_socket":"control","container_port":8081}],"public_environment":[],"configuration_artifacts":[],"secret_deliveries":[],"retained_data_mounts":[{"resource_id":"provider-data","target_path":"/var/lib/cpk-secrets"}],"capabilities":["health-checkable"],"verification":{"checks":[{"kind":"http","check_id":"live","provider_socket":"control","policy":{"timeout_seconds":5.0,"interval_seconds":1.0,"maximum_attempts":10,"maximum_evidence_bytes":16384},"path":"/health/live","expected_statuses":[200]},{"kind":"http","check_id":"ready","provider_socket":"control","policy":{"timeout_seconds":5.0,"interval_seconds":1.0,"maximum_attempts":10,"maximum_evidence_bytes":16384},"path":"/health/ready","expected_statuses":[200]}]},"lifecycle":{"ownership":"owned","compute":"ephemeral","data":[{"resource_id":"provider-data","persistence":"retained"}]}},"display_name":"secrets-server","description":"Encrypted durable secret provider with a private HTTP control socket and retained custody store. Root bootstrap key and provider credential files are supplied by trusted preflight infrastructure under the adjacent non-recursive bootstrap contract. They never enter this descriptor.","product_family":"data-service"}}'

PUBLISHED_BOOTSTRAP_CONTRACT = b'{\n  "schema": "cpk-secrets.bootstrap-contract",\n  "environment": [\n    {\n      "name": "CPK_SECRETS_DATABASE_PATH",\n      "required": true,\n      "allowed_values": [\n        "absolute path under the retained provider-data mount"\n      ]\n    },\n    {\n      "name": "CPK_SECRETS_MASTER_KEY_FILE",\n      "required": true,\n      "allowed_values": [\n        "absolute owner-readable mounted file"\n      ]\n    },\n    {\n      "name": "CPK_SECRETS_CREDENTIALS_FILE",\n      "required": true,\n      "allowed_values": [\n        "absolute owner-readable mounted file"\n      ]\n    },\n    {\n      "name": "CPK_SECRETS_PROVIDER_ID",\n      "required": true,\n      "allowed_values": [\n        "bounded provider identity"\n      ]\n    }\n  ],\n  "bootstrap_files": [\n    {\n      "purpose": "provider master encryption key",\n      "environment_name": "CPK_SECRETS_MASTER_KEY_FILE",\n      "default_target": "/run/secrets/cpk-secrets/master.key",\n      "maximum_bytes": 4096,\n      "mode": "0400"\n    },\n    {\n      "purpose": "provider API credentials and grants",\n      "environment_name": "CPK_SECRETS_CREDENTIALS_FILE",\n      "default_target": "/run/secrets/cpk-secrets/credentials.json",\n      "maximum_bytes": 65536,\n      "mode": "0400"\n    }\n  ],\n  "runtime_inputs": [\n    "root provider bootstrap files are supplied by trusted preflight infrastructure",\n    "bootstrap files are not product configuration artifacts and never enter the product descriptor",\n    "bootstrap files are not recursively resolved through the provider being started",\n    "a nested provider may later receive equivalent files from an already admitted parent provider",\n    "provider responses, logs, errors, observations, and catalogue metadata never contain bootstrap values"\n  ]\n}\n'


class FixtureJournal:
    """Fixture-only intent/identity evidence; never a production journal service."""

    def __init__(self, directory, fixture, sdk, helper_image):
        import json
        import os
        from pathlib import Path
        self.fixture, self.sdk, self.helper_image = fixture, sdk, helper_image
        self.client = sdk._client()
        self.failed = False
        self.helpers = []
        self._helper_scope = None
        self._attempts = set()
        self._json, self._os = json, os
        path = Path(directory) / "journal.jsonl"
        self._file = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w")
        self.write({"phase": "prepared", "network": fixture.network,
                    "network_labels": fixture.network_labels, "recipient": fixture.recipient,
                    "node_labels": fixture.node_labels, "volumes": fixture.volume_labels,
                    "image": IMAGE_REFERENCE, "helper_limit": 4})

    def write(self, record):
        if self.failed:
            raise RuntimeError("fixture journal unavailable")
        try:
            line = self._json.dumps(record, separators=(",", ":"), sort_keys=True)
            if len(line.encode()) > 65536:
                raise RuntimeError("fixture record bound exceeded")
            self._file.write(line + "\n")
            self._file.flush()
            self._os.fsync(self._file.fileno())
        except Exception:
            self.failed = True
            raise

    def observed(self, record):
        # Post-effect evidence failure must not replace the provider's response.
        try:
            self.write(record)
        except Exception:
            self.failed = True

    def __enter__(self):
        sdk, api = self.sdk, self.client.api
        self._originals = (sdk.create_network, sdk.create_volume, sdk.create_container,
                           sdk.start_container, sdk._create_configuration_helper, api.create_container)
        create_network, create_volume, create_recipient, start_recipient, create_helper, api_create = self._originals

        def guarded(kind, original, name, expected, args, kwargs):
            if name not in expected or kwargs.get("labels") != expected[name] or (kind, name) in self._attempts:
                raise RuntimeError("fixture effect identity mismatch")
            self.write({"phase": "pending", "kind": kind, "name": name})
            self._attempts.add((kind, name))
            try:
                result = original(*args, **kwargs)
            except Exception:
                self.observed({"phase": "raised", "kind": kind, "name": name})
                raise
            self.observed({"phase": "returned", "kind": kind, "name": name})
            return result

        def network(*args, **kwargs):
            return guarded("network-create", create_network, kwargs.get("name"),
                           {self.fixture.network: self.fixture.network_labels}, args, kwargs)

        def volume(*args, **kwargs):
            return guarded("volume-create", create_volume, kwargs.get("name"),
                           self.fixture.volume_labels, args, kwargs)

        def recipient(*args, **kwargs):
            return guarded("recipient-create", create_recipient, kwargs.get("name"),
                           {self.fixture.recipient: self.fixture.node_labels}, args, kwargs)

        def start(name):
            if name != self.fixture.recipient or ("recipient-start", name) in self._attempts:
                raise RuntimeError("fixture start identity mismatch")
            self.write({"phase": "pending", "kind": "recipient-start", "name": name})
            self._attempts.add(("recipient-start", name))
            result = start_recipient(name)
            self.observed({"phase": "returned", "kind": "recipient-start", "name": name})
            return result

        def helper(volume_name, *, readonly):
            if volume_name not in self.fixture.secret_volumes or self._helper_scope is not None:
                raise RuntimeError("fixture helper volume mismatch")
            self._helper_scope = (volume_name, readonly)
            try:
                return create_helper(volume_name, readonly=readonly)
            finally:
                self._helper_scope = None

        def api_container(*args, **kwargs):
            if self._helper_scope is None:
                return api_create(*args, **kwargs)
            if len(self.helpers) >= 4:
                raise RuntimeError("fixture helper count exceeded")
            volume_name, readonly = self._helper_scope
            name = kwargs.get("name")
            if not isinstance(name, str) or not name.startswith("cpk-config-"):
                raise RuntimeError("fixture helper identity unavailable")
            record = {"name": name, "id": None, "volume": volume_name, "readonly": readonly}
            self.write({"phase": "pending", "kind": "helper", **record})
            self.helpers.append(record)
            result = api_create(*args, **kwargs)
            identity = result.get("Id") if isinstance(result, dict) else None
            if isinstance(identity, str) and identity:
                record["id"] = identity
                self.observed({"phase": "returned", "kind": "helper", **record})
            else:
                self.failed = True
            return result

        sdk.create_network, sdk.create_volume, sdk.create_container = network, volume, recipient
        sdk.start_container, sdk._create_configuration_helper, api.create_container = start, helper, api_container
        return self

    def __exit__(self, exc_type, exc, traceback):
        (self.sdk.create_network, self.sdk.create_volume, self.sdk.create_container,
         self.sdk.start_container, self.sdk._create_configuration_helper,
         self.client.api.create_container) = self._originals
        return False

    def cleanup(self):
        """Only authoritative, exact planned/recorded resource identities."""
        import docker
        client, fixture = self.client, self.fixture
        if self.failed:
            return False
        try:
            try:
                recipient = client.containers.get(fixture.recipient)
            except docker.errors.NotFound:
                recipient = None
            if recipient is not None:
                if (recipient.attrs["Config"].get("Labels") != fixture.container_labels
                        or recipient.attrs["Image"] != fixture.image_id
                        or recipient.attrs["Config"].get("User") != "10006"):
                    raise RuntimeError("fixture recipient ownership mismatch")
                networks = recipient.attrs["NetworkSettings"]["Networks"]
                if set(networks) != {fixture.network}:
                    raise RuntimeError("fixture recipient attachment mismatch")
                self.write({"phase": "cleanup-pending", "kind": "recipient", "id": recipient.id})
                recipient.remove(force=True)
                self._require_absent(client.containers, recipient.id)
            for helper in self.helpers:
                if helper["id"] is None:
                    # Name alone cannot establish ownership of an unlabeled helper.
                    raise RuntimeError("fixture helper identity unresolved")
                try:
                    resource = client.containers.get(helper["id"])
                except docker.errors.NotFound:
                    resource = None
                if resource is None:
                    continue
                mounts = resource.attrs.get("Mounts", [])
                if (resource.name != helper["name"] or resource.attrs["Image"] != self.helper_image
                        or resource.attrs["Config"].get("NetworkDisabled") is not True
                        or len(mounts) != 1 or mounts[0].get("Name") != helper["volume"]
                        or mounts[0].get("RW") != (not helper["readonly"])):
                    raise RuntimeError("fixture helper conformance mismatch")
                self.write({"phase": "cleanup-pending", "kind": "helper", "id": resource.id})
                resource.remove(force=True)
                self._require_absent(client.containers, resource.id)
            for name, labels in fixture.volume_labels.items():
                try:
                    volume = client.volumes.get(name)
                except docker.errors.NotFound:
                    volume = None
                if volume is None:
                    continue
                if volume.attrs.get("Labels") != labels or client.containers.list(all=True, filters={"volume": name}):
                    raise RuntimeError("fixture volume ownership or attachment mismatch")
                self.write({"phase": "cleanup-pending", "kind": "volume", "id": volume.name})
                volume.remove()
                self._require_absent(client.volumes, volume.name)
            try:
                network = client.networks.get(fixture.network)
            except docker.errors.NotFound:
                network = None
            if network is not None:
                if network.attrs.get("Labels") != fixture.network_labels or network.attrs.get("Containers"):
                    raise RuntimeError("fixture network ownership or attachment mismatch")
                self.write({"phase": "cleanup-pending", "kind": "network", "id": network.id})
                network.remove()
                self._require_absent(client.networks, network.id)
            return True
        except Exception:
            self.observed({"phase": "cleanup-hold"})
            return False

    def _require_absent(self, manager, identity):
        import docker
        try:
            manager.get(identity)
        except docker.errors.NotFound:
            self.observed({"phase": "absence-verified", "id": identity})
            return
        raise RuntimeError("fixture residue present")

    def close(self):
        self._file.close()


def _recipient_conformance(client, fixture, image_id):
    container = client.containers.get(fixture.recipient)
    attrs = container.attrs
    host = attrs["HostConfig"]
    networks = attrs["NetworkSettings"]["Networks"]
    mounts = host.get("Mounts") or []
    expected_mounts = {(name, target) for name,target in zip(fixture.secret_volumes, fixture.targets)}
    observed_mounts = {(item.get("Source"), item.get("Target")) for item in mounts}
    if (attrs["Image"] != image_id or attrs["Config"].get("User") != "10006"
            or attrs["Config"].get("Labels") != fixture.container_labels
            or not attrs["State"]["Running"] or set(networks) != {fixture.network}
            or fixture.material.node_id not in (networks[fixture.network].get("Aliases") or [])
            or host.get("PortBindings") or len(mounts) != 2 or observed_mounts != expected_mounts
            or any(m.get("Type") != "volume" or m.get("ReadOnly") is not True
                   or m.get("VolumeOptions", {}).get("Subpath") != "content" for m in mounts)
            or host.get("Binds") != [fixture.data_volume + ":/var/lib/cpk-secrets:rw"]):
        raise RuntimeError("fixture recipient conformance failed")
    return container


def _recipient_file_probe(client, container, fixture, journal):
    import json
    import time
    script = '''import errno,hashlib,http.client,json,os,stat,time
ok=False
try:
 assert os.getuid()==10006
 targets=TARGETS
 digests=DIGESTS
 for path,digest in zip(targets,digests):
  with open(path,'rb') as file: content=file.read(65537)
  assert len(content)<=65536 and hashlib.sha256(content).hexdigest()==digest
  info=os.stat(path)
  assert info.st_uid==10006 and stat.S_IMODE(info.st_mode)==0o400
  try: fd=os.open(path,os.O_WRONLY)
  except OSError as error: assert error.errno in (errno.EACCES,errno.EPERM,errno.EROFS)
  else:
   os.close(fd)
   raise RuntimeError('readonly assertion failed')
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  connection=http.client.HTTPConnection('127.0.0.1',8081,timeout=min(1,deadline-time.monotonic()))
  try:
   connection.request('GET','/health/ready')
   if connection.getresponse().status==200:
    ok=True
    break
  except (OSError,http.client.HTTPException): ready=False
  finally: connection.close()
  time.sleep(0.1)
except Exception: ok=False
print(json.dumps({'files_and_readiness':ok}))
raise SystemExit(0 if ok else 1)
'''.replace("TARGETS", repr(fixture.targets)).replace("DIGESTS", repr(fixture.digests))
    journal.write({"phase": "pending", "kind": "recipient-exec", "id": container.id,
                   "internal_seconds": 15, "controller_seconds": 20, "output_bytes": 4096})
    api = client.api
    prior_timeout = api.timeout
    deadline = time.monotonic() + 20
    output = bytearray()
    stream = None
    try:
        api.timeout = 20
        invocation = api.exec_create(container.id,
            ["timeout", "--signal=KILL", "15s", "python", "-B", "-c", script],
            stdout=True, stderr=True, privileged=False)
        exec_id = invocation["Id"]
        journal.write({"phase": "exec-created", "id": exec_id, "recipient_id": container.id})
        api.timeout = max(0.1, deadline - time.monotonic())
        stream = api.exec_start(exec_id, stream=True, demux=False)
        for chunk in stream:
            if time.monotonic() >= deadline or len(output) + len(chunk) > 4096:
                raise RuntimeError("fixture exec bound exceeded")
            output.extend(chunk)
        api.timeout = max(0.1, deadline - time.monotonic())
        completed = api.exec_inspect(exec_id)
        if time.monotonic() >= deadline or completed.get("Running") or completed.get("ExitCode") != 0:
            raise RuntimeError("fixture exec did not pass")
        if json.loads(output.decode("utf-8")) != {"files_and_readiness": True}:
            raise RuntimeError("fixture file readiness evidence failed")
        journal.write({"phase": "exec-passed", "files_and_readiness": True})
    finally:
        api.timeout = prior_timeout
        output.clear()
        if stream is not None:
            stream.close()


def run_provider_contract(client, sdk, helper_image, run_id, record_directory):
    """One separately admitted provider attempt in the existing gate controller."""
    import docker
    import json
    import os
    from control_plane_kit_core.operations.execution import EffectResultKind
    from control_plane_kit_interpreters.docker import DockerRuntimeInterpreter

    fixture = prepare_fixture(run_id)
    image = client.images.get(IMAGE_REFERENCE)
    if (IMAGE_REFERENCE not in (image.attrs.get("RepoDigests") or [])
            or image.attrs.get("Os") != "linux" or image.attrs.get("Architecture") != "amd64"
            or image.attrs["Config"].get("User") != "10006"
            or client.info().get("ID") != os.environ["CPK_SECRET_ENGINE_ID"]):
        raise RuntimeError("fixture image or engine admission failed")
    fixture.container_labels = {**(image.attrs["Config"].get("Labels") or {}), **fixture.node_labels}
    fixture.image_id = image.id
    for manager,name in [(client.networks, fixture.network), (client.containers, fixture.recipient),
                         *((client.volumes, name) for name in fixture.volume_labels)]:
        try:
            manager.get(name)
        except docker.errors.NotFound:
            absent = True
        else:
            absent = False
        if not absent:
            raise RuntimeError("fixture proposed identity already exists")
    journal = FixtureJournal(record_directory, fixture, sdk, helper_image)
    observation = ProviderContractObservation(sdk, fixture.recipient,
        lambda result: journal.observed({"phase": "observation", "diagnostic": result}))
    passed = False
    terminal_kind = "not-reached"
    try:
        with journal, observation:
            interpreter = DockerRuntimeInterpreter(sdk, authorized_secret_resolver=fixture.resolver)
            runtime = interpreter.execute(fixture.start)
            if runtime.kind is not EffectResultKind.SUCCEEDED:
                terminal_kind = "runtime-" + runtime.kind.value
                raise RuntimeError("fixture runtime did not succeed")
            node = interpreter.execute(fixture.node)
            terminal_kind = node.kind.value
            report = observation.report()
            if (node.kind is not EffectResultKind.SUCCEEDED or not report["diagnostic_available"]
                    or report["pull_attempted"] or report["create"]["outcome"] != "returned"
                    or report["inspect"]["outcome"] != "returned" or len(journal.helpers) != 4):
                raise RuntimeError("fixture StartNode or diagnostic did not succeed")
            container = _recipient_conformance(client, fixture, image.id)
            journal.write({"phase": "recipient-conformance", "id": container.id,
                           "image_network_mount_user_running": True})
            _recipient_file_probe(client, container, fixture, journal)
            passed = not journal.failed
    except Exception:
        passed = False
    finally:
        cleaned = journal.cleanup()
        final = {"status": "passed" if passed and cleaned and not journal.failed else "HOLD",
                 "runtime_result": terminal_kind, "diagnostic": observation.report(),
                 "recipient_conformance": passed, "synthetic_resources_absent_at_observation": cleaned,
                 "journal_available": not journal.failed}
        journal.observed({"phase": "terminal", **final})
        final["journal_available"] = not journal.failed
        if journal.failed:
            final["status"] = "HOLD"
        journal.close()
        print(json.dumps({"start_node_provider_contract": final}, separators=(",", ":")))
    if final["status"] != "passed":
        raise RuntimeError("isolated StartNode provider contract HOLD")
