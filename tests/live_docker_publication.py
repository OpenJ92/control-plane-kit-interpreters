"""Live Docker proof for host publication and endpoint observations."""

from __future__ import annotations

import json
from uuid import uuid4

from control_plane_kit_core.probe_intents import EndpointContext
from control_plane_kit_core.types import Protocol, Transport

from control_plane_kit_interpreters.docker import (
    DockerSdkClient,
    DockerSdkPortBinding,
    runtime_endpoint_observations,
    verify_published_ports,
)


def main() -> None:
    suffix = uuid4().hex[:12]
    network_name = f"cpk-live-publication-{suffix}"
    container_name = f"cpk-live-publication-{suffix}"
    labels = {
        "control-plane-kit.live-proof": "host-publication",
        "control-plane-kit.disposable": "true",
    }
    provider_ports = (
        DockerSdkPortBinding(
            "http",
            Protocol.HTTP,
            8000,
            "127.0.0.1",
            None,
        ),
        DockerSdkPortBinding(
            "dns-udp",
            Protocol.DNS_UDP,
            5353,
            "127.0.0.1",
            None,
        ),
    )
    sdk = DockerSdkClient()

    try:
        sdk.pull_image(sdk.configuration_helper_image)
        sdk.create_network(name=network_name, labels=labels)
        sdk.run_container(
            name=container_name,
            image=sdk.configuration_helper_image,
            network=network_name,
            aliases=(container_name,),
            environment={},
            labels=labels,
            volumes={},
            command=("python", "-B", "-c", "import time; time.sleep(30)"),
            port_bindings=provider_ports,
        )
        inspected = sdk.inspect_container(container_name)
        if inspected is None:
            raise AssertionError("published container was not inspectable")
        published = inspected.published_ports
        transports = {(value.container_port, value.transport) for value in published}
        if transports != {(8000, Transport.TCP), (5353, Transport.UDP)}:
            raise AssertionError(f"unexpected published ports: {published!r}")
        verified = verify_published_ports(provider_ports, published)
        observations = runtime_endpoint_observations(
            subject_id=container_name,
            graph_id="live-publication-graph",
            private_host=container_name,
            provider_ports=provider_ports,
            published_ports=verified,
        )
        host_observed = tuple(
            value
            for value in observations
            if value.context is EndpointContext.HOST_LOCAL
        )
        if len(host_observed) != 2:
            raise AssertionError("expected one host-local observation per publication")
    finally:
        _cleanup(sdk, container_name, network_name)

    print(
        json.dumps(
            {
                "status": "passed",
                "published_ports": [
                    {
                        "container_port": value.container_port,
                        "transport": value.transport.value,
                    }
                    for value in published
                ],
                "host_observations": len(host_observed),
            },
            sort_keys=True,
        )
    )


def _cleanup(
    sdk: DockerSdkClient,
    container_name: str,
    network_name: str,
) -> None:
    for action, name in (
        (sdk.remove_container, container_name),
        (sdk.remove_network, network_name),
    ):
        try:
            action(name)
        except Exception:
            pass


if __name__ == "__main__":
    main()
