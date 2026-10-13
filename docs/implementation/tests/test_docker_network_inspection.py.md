# Exact Docker network inspection targets (#194)

Seven methods extend the existing SDK read-projection laws on accepted I189.
They use the established fake Docker client/resource, without Core/Operations
state-machine emulation. Direct public inspection calls establish actual missing
field/value failures; there is no common missing-module assertion hiding every
body. Existing absence/provider-error/client-lifetime behavior is also exercised.

Positive laws preserve network ID by name/ID lookup, container ID and same-payload
membership/address association, deterministic order, immutable snapshot, changed
ID despite unchanged names, public frozen value and validated construction.
Unknown metadata, observed empty membership and known addressless membership are
three different facts. Old fixtures lacking NetworkID cannot invent identities.

Target design caps membership count at 64 and requires canonical 64-character
lowercase hexadecimal Docker IDs and bounded numeric unscoped addresses from the
existing IPAddress field. Invalid/duplicate/excessive values fail with bounded
redacted errors. Missing identity keys yield unavailable evidence; a present
malformed identity (including null) is invalid. This adds no provider call,
mutation, client ownership, route/health claim, dependency or authority.

Owning validation is unchanged pinned ./test.sh. Targets await exact review and
causal red; no implementation or executable validation has run for #194.
