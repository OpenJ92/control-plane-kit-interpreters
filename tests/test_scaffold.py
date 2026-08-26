from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import unittest

import control_plane_kit_interpreters
from control_plane_kit_interpreters import INTERPRETER_SPINE
from control_plane_kit_interpreters.boundaries import INTERPRETERS_BOUNDARY


class InterpretersScaffoldTests(unittest.TestCase):
    def test_package_root_exports_only_lightweight_boundary_values(self) -> None:
        self.assertEqual(
            control_plane_kit_interpreters.__all__,
            [
                "INTERPRETER_SPINE",
                "InterpreterBoundary",
            ],
        )
        self.assertEqual(
            INTERPRETER_SPINE,
            (
                "cpk-server",
                "configured operations application",
                "ExecutionCoordinator",
                "RuntimeInterpreterDispatcher",
                "DockerRuntimeInterpreter",
                "Python Docker SDK",
            ),
        )

    def test_boundary_marker_denies_dispatch_and_server_process_ownership(self) -> None:
        self.assertEqual(
            INTERPRETERS_BOUNDARY.package,
            "control-plane-kit-interpreters",
        )
        self.assertTrue(INTERPRETERS_BOUNDARY.owns_concrete_effects)
        self.assertFalse(INTERPRETERS_BOUNDARY.owns_durable_dispatch)
        self.assertFalse(INTERPRETERS_BOUNDARY.owns_server_process)

    def test_base_import_does_not_eagerly_import_optional_runtime_packages(self) -> None:
        script = """
import sys
import control_plane_kit_interpreters

for name in (
    "docker",
    "fastapi",
    "psycopg",
    "control_plane_kit_operations",
    "control_plane_kit_servers_cpk_server",
):
    assert name not in sys.modules, name
"""

        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            text=True,
            capture_output=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)


_PROBE_EXPORT_OWNERS = {
    "AuthorizedProbeTarget": "security",
    "DefaultDatagramExchangeClient": "clients",
    "DefaultSocketConnector": "clients",
    "DnsOverHttpsPublicAddressResolver": "public_dns",
    "Ed25519GatewayProbeSigner": "gateway",
    "GatewayProbeClientCode": "gateway",
    "GatewayProbeClientError": "gateway",
    "GatewayProbeClientResult": "gateway",
    "HttpApplicationHealthProbeAdapter": "clients",
    "ProbeAddressPolicy": "security",
    "ProbeSecurityCode": "security",
    "ProbeSecurityError": "security",
    "PublicDnsResolutionCode": "public_dns",
    "PublicDnsResolutionError": "public_dns",
    "PublicDnsResolverPolicy": "public_dns",
    "StaticRuntimeEndpointProvider": "clients",
    "SignedGatewayProbeClient": "gateway",
    "TcpTransportProbeAdapter": "clients",
    "TransportProbeRouter": "clients",
    "UdpTransportProbeAdapter": "clients",
    "UnsupportedTransportProbe": "clients",
    "authorize_probe_endpoint": "security",
}


_COLD_IMPORT_GUARDS = """
import importlib
import importlib.abc
import importlib.util
import json
import sys

blocked, required, export_owners = json.loads(sys.argv[1])
assert not any(name.startswith("control_plane_kit_interpreters") for name in sys.modules)
for root in required:
    assert importlib.util.find_spec(root) is not None, ("missing apparatus dependency", root)
for root in blocked:
    assert not any(name == root or name.startswith(root + ".") for name in sys.modules)

denied_imports = []
class DenyUnselectedDependency(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.partition(".")[0] in blocked:
            denied_imports.append(fullname)
            raise ModuleNotFoundError("dependency denied by import law", name=fullname)

sys.meta_path.insert(0, DenyUnselectedDependency())
# Prove the denial hook itself works before testing the candidate imports.
for root in blocked:
    try:
        importlib.import_module(root)
    except ModuleNotFoundError as error:
        assert error.name == root
    else:
        raise AssertionError(("denial hook bypassed", root))
denied_imports.clear()

provider_events = []
class ImportTimeProviderIO(RuntimeError):
    pass

def forbid_provider_io(event, args):
    if event in {
        "socket.connect", "socket.connect_ex", "socket.bind", "socket.sendto",
        "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr",
        "subprocess.Popen", "os.system", "os.posix_spawn", "os.posix_spawnp",
    }:
        provider_events.append(event)
        raise ImportTimeProviderIO("provider IO during import")

sys.addaudithook(forbid_provider_io)
"""


class OptionalProbeImportIsolationTests(unittest.TestCase):
    def _cold_import(
        self,
        script: str,
        *,
        blocked: tuple[str, ...] = (),
        required: tuple[str, ...] = (),
    ) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                _COLD_IMPORT_GUARDS
                + textwrap.dedent(script)
                + "\nassert provider_events == [], provider_events\n",
                json.dumps((blocked, required, _PROBE_EXPORT_OWNERS)),
            ],
            check=False,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_docker_imports_do_not_require_dns_or_gateway_dependencies(self) -> None:
        for module, name in (
            ("docker.runtime", "DockerRuntimeInterpreter"),
            ("docker.observer", "DockerRuntimeEffectObserver"),
            ("probes.security", "ProbeAddressPolicy"),
        ):
            with self.subTest(module=module):
                self._cold_import(
                    f"""
                    selected = importlib.import_module("control_plane_kit_interpreters.{module}")
                    assert getattr(selected, "{name}").__name__ == "{name}"
                    assert denied_imports == [], denied_imports
                    """,
                    blocked=("dns", "jwt", "cryptography"),
                    required=("httpx", "docker"),
                )

    def test_gateway_exports_do_not_require_dns_dependencies(self) -> None:
        self._cold_import(
            """
            facade = importlib.import_module("control_plane_kit_interpreters.probes")
            for name, owner in export_owners.items():
                if owner == "gateway":
                    selected = getattr(facade, name)
                    concrete = importlib.import_module("control_plane_kit_interpreters.probes.gateway")
                    assert selected is getattr(concrete, name), name
            assert denied_imports == [], denied_imports
            """,
            blocked=("dns",),
            required=("httpx", "jwt", "cryptography"),
        )

    def test_public_dns_exports_do_not_require_gateway_dependencies(self) -> None:
        self._cold_import(
            """
            facade = importlib.import_module("control_plane_kit_interpreters.probes")
            for name, owner in export_owners.items():
                if owner == "public_dns":
                    selected = getattr(facade, name)
                    concrete = importlib.import_module("control_plane_kit_interpreters.probes.public_dns")
                    assert selected is getattr(concrete, name), name
            assert denied_imports == [], denied_imports
            """,
            blocked=("jwt", "cryptography"),
            required=("dns", "httpx"),
        )

    def test_unselected_facade_and_unknown_attributes_need_no_optional_backend(self) -> None:
        self._cold_import(
            """
            facade = importlib.import_module("control_plane_kit_interpreters.probes")
            assert facade.__all__ == list(export_owners)
            for name in ("unknown_probe", "scenario_payload", "__unknown_backend__"):
                try:
                    getattr(facade, name)
                except AttributeError:
                    pass
                else:
                    raise AssertionError(("unexpected public attribute", name))
            assert denied_imports == [], denied_imports
            """,
            blocked=("httpx", "dns", "jwt", "cryptography", "docker", "psycopg"),
        )

    def test_selected_backend_missing_dependency_is_not_suppressed(self) -> None:
        for name, dependency in (
            ("Ed25519GatewayProbeSigner", "jwt"),
            ("Ed25519GatewayProbeSigner", "cryptography"),
            ("DnsOverHttpsPublicAddressResolver", "dns"),
            ("HttpApplicationHealthProbeAdapter", "httpx"),
        ):
            with self.subTest(export=name, missing=dependency):
                self._cold_import(
                    f"""
                    try:
                        facade = importlib.import_module("control_plane_kit_interpreters.probes")
                        getattr(facade, "{name}")
                    except ModuleNotFoundError as error:
                        assert error.name.partition(".")[0] == "{dependency}", error.name
                        assert denied_imports, "selected dependency was not attempted"
                    else:
                        raise AssertionError("missing selected dependency was concealed")
                    """,
                    blocked=(dependency,),
                    required=tuple(
                        root for root in ("httpx", "dns", "jwt", "cryptography")
                        if root != dependency
                    ),
                )

    def test_public_export_catalog_and_concrete_object_identity_are_preserved(self) -> None:
        self._cold_import(
            """
            facade = importlib.import_module("control_plane_kit_interpreters.probes")
            assert facade.__all__ == list(export_owners)
            assert len(set(facade.__all__)) == len(export_owners)
            for name, owner in export_owners.items():
                selected = getattr(facade, name)
                concrete = importlib.import_module("control_plane_kit_interpreters.probes." + owner)
                assert selected is getattr(concrete, name), name
                assert getattr(facade, name) is selected, name
            """,
            required=("httpx", "dns", "jwt", "cryptography"),
        )

    def test_import_and_export_resolution_perform_no_provider_io(self) -> None:
        self._cold_import(
            """
            for event in ("socket.connect", "socket.getaddrinfo", "subprocess.Popen"):
                try:
                    sys.audit(event)
                except ImportTimeProviderIO:
                    assert provider_events == [event]
                    provider_events.clear()
                else:
                    raise AssertionError("provider IO guard was not armed")
            facade = importlib.import_module("control_plane_kit_interpreters.probes")
            for name in export_owners:
                getattr(facade, name)
            importlib.import_module("control_plane_kit_interpreters.docker")
            """,
            required=("httpx", "dns", "jwt", "cryptography", "docker"),
        )

    def test_selected_backend_preserves_unexpected_import_exception_identity(self) -> None:
        self._cold_import(
            """
            original = RuntimeError("selected backend programming failure")
            class FailingBackend(importlib.abc.MetaPathFinder):
                def find_spec(self, fullname, path=None, target=None):
                    if fullname == "control_plane_kit_interpreters.probes.public_dns":
                        raise original
            sys.meta_path.insert(0, FailingBackend())
            try:
                facade = importlib.import_module("control_plane_kit_interpreters.probes")
                getattr(facade, "DnsOverHttpsPublicAddressResolver")
            except RuntimeError as error:
                assert error is original
            else:
                raise AssertionError("unexpected import exception was concealed")
            """,
            required=("httpx", "dns", "jwt", "cryptography"),
        )


if __name__ == "__main__":
    unittest.main()
