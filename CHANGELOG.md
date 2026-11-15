# Changelog

## 0.5.1

- My grants (app), `grants list` and `grants revoke` (CLI) show the new grant
  statuses of the website: `inactive` (the grant is still stored, but the
  account is not delegated to Helix7702Account; it becomes active again if the
  account re-delegates), `missing` as "not installed", and `unavailable` only
  for a temporary chain read failure, with a retry hint. An unknown status is
  shown as it is, and Revoke is only offered when the website says the grant is
  revocable.
- Revoking a dormant grant of an account whose EIP-7702 delegation was cleared
  now works: the signer reads the grant from the account's storage, sends one
  type-4 transaction whose authorization (nonce + 1) re-delegates the account
  to the pinned implementation and revokes the grant, then verifies the
  delegation and the cleared key on chain. A grant under another contract's
  delegation is still refused, with an explanation.
- "Revoke all active" includes dormant (`inactive`) grants the signer can revoke.

## 0.5.0

- Initial open-source release.
