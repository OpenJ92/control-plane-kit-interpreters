from __future__ import annotations

import unittest

from control_plane_kit_core.secrets import (
    LocalDevelopmentSecretResolver,
    SecretEnvironmentDelivery,
    SecretFileDelivery,
    SecretFileMode,
    SecretFilePathBinding,
    SecretProviderAuthority,
    SecretProviderId,
    SecretReference,
    SecretReferenceEnvironmentDelivery,
    SecretResolutionCode,
    SecretResolutionError,
)

from control_plane_kit_interpreters.secrets import (
    SecretFileRuntimeMaterial,
    resolve_secret_deliveries,
)


SECRET_TEXT = "correct-horse-battery-staple"


class SecretDeliveryTests(unittest.TestCase):
    def test_resolves_environment_reference_and_file_deliveries(self) -> None:
        reference = SecretReference("secret://local/workspace-a/api-token")
        result = resolve_secret_deliveries(
            (
                SecretEnvironmentDelivery("API_TOKEN", reference),
                SecretReferenceEnvironmentDelivery("API_TOKEN_REF", reference),
                SecretFileDelivery(
                    "/run/secrets/api-token",
                    reference,
                    SecretFileMode.OWNER_READ_ONLY,
                    SecretFilePathBinding("API_TOKEN_FILE"),
                ),
            ),
            resolver=_resolver(),
        )

        self.assertEqual(
            dict(result.environment),
            {
                "API_TOKEN": SECRET_TEXT,
                "API_TOKEN_REF": "secret://local/workspace-a/api-token",
                "API_TOKEN_FILE": "/run/secrets/api-token",
            },
        )
        self.assertEqual(
            result.files,
            (
                SecretFileRuntimeMaterial(
                    reference,
                    "/run/secrets/api-token",
                    result.files[0].value,
                    SecretFileMode.OWNER_READ_ONLY,
                    "API_TOKEN_FILE",
                ),
            ),
        )
        self.assertEqual(result.files[0].value.reveal(), SECRET_TEXT)
        self.assertNotIn(SECRET_TEXT, repr(result))

    def test_missing_resolver_fails_before_runtime_mutation(self) -> None:
        with self.assertRaises(SecretResolutionError) as raised:
            resolve_secret_deliveries(
                (
                    SecretEnvironmentDelivery(
                        "API_TOKEN",
                        SecretReference("secret://local/workspace-a/api-token"),
                    ),
                ),
                resolver=None,
            )

        self.assertIs(raised.exception.code, SecretResolutionCode.MISSING)
        self.assertNotIn(SECRET_TEXT, repr(raised.exception))

    def test_missing_or_denied_reference_is_bounded_and_redacted(self) -> None:
        for resolver, expected_code in (
            (_resolver(values={}), SecretResolutionCode.MISSING),
            (
                LocalDevelopmentSecretResolver(
                    SecretProviderAuthority(SecretProviderId("other")),
                    {},
                ),
                SecretResolutionCode.DENIED,
            ),
        ):
            with self.subTest(expected_code=expected_code):
                with self.assertRaises(SecretResolutionError) as raised:
                    resolve_secret_deliveries(
                        (
                            SecretFileDelivery(
                                "/run/secrets/api-token",
                                SecretReference("secret://local/workspace-a/api-token"),
                            ),
                        ),
                        resolver=resolver,
                    )

                self.assertIs(raised.exception.code, expected_code)
                self.assertNotIn(SECRET_TEXT, repr(raised.exception))

    def test_conflicting_secret_environment_delivery_fails_closed(self) -> None:
        with self.assertRaises(SecretResolutionError) as raised:
            resolve_secret_deliveries(
                (
                    SecretEnvironmentDelivery(
                        "API_TOKEN",
                        SecretReference("secret://local/workspace-a/api-token"),
                    ),
                    SecretReferenceEnvironmentDelivery(
                        "API_TOKEN",
                        SecretReference("secret://local/workspace-a/api-token"),
                    ),
                ),
                resolver=_resolver(),
            )

        self.assertIs(
            raised.exception.code,
            SecretResolutionCode.MALFORMED_REFERENCE,
        )


def _resolver(
    *,
    values: dict[str, str] | None = None,
) -> LocalDevelopmentSecretResolver:
    return LocalDevelopmentSecretResolver(
        SecretProviderAuthority(SecretProviderId("local")),
        {
            "secret://local/workspace-a/api-token": SECRET_TEXT,
            **({} if values is None else values),
        }
        if values is None
        else values,
    )


if __name__ == "__main__":
    unittest.main()
