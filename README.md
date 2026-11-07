# LicenseLedger

Bonded license-compliance certificates on GenLayer. An attester stakes GEN that a GitHub repository, pinned to one exact 40-character commit SHA, complies with a declared SPDX license (the `LICENSE` file and, optionally, a manifest such as `package.json`). GenLayer validators fetch the pinned files from `raw.githubusercontent.com` themselves and must agree on a categorical verdict: `COMPLIANT`, `NON_COMPLIANT` or `UNDETERMINED`. A challenger can contest a pending certificate by matching the bond and citing another file from the same commit. Finished certificates are readable by other contracts through a small on-chain registry.

## What is different from the other contracts in this series

This is a registry of facts about immutable content, not an escrow between two parties. Because the commit SHA is part of every URL, the files can never change after the attestation, so the only risk is a wrong verdict, and the bonded challenge covers exactly that. The verdict is never a bare "the AI decided":

1. **Pinned URLs built in code.** The contract never accepts a URL. It builds `https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}` itself from validated parts. Branches, tags, short SHAs, `..`, encoded separators, queries, credentials and other hosts cannot get through.
2. **License anchor.** The `LICENSE` text must contain the standard markers of the declared SPDX license (for example the MIT grant sentence, or the GPL-3.0 title and version leading the file). If it does not, the verdict is `NON_COMPLIANT` without any model call.
3. **Manifest anchor.** When a manifest is attested, it must declare the same SPDX identifier as a whole token, otherwise `COMPLIANT` is impossible.
4. **Quoted verdicts.** `COMPLIANT` needs an exact quote from the `LICENSE` file (and from the manifest when present). A model-derived `NON_COMPLIANT` needs an exact quote showing the conflict, taken from the counter-evidence file during a challenge. A verdict without a real quote is downgraded to `UNDETERMINED`.
5. **Bonded challenge.** The challenger matches the attester bond. An upheld challenge pays the challenger both bonds and revokes the commit and license pair for good; a rejected one pays the challenger bond to the attester. Challenges never shorten the challenge window.

## Contract

`contracts/licenseledger.py` (single file, no comments, deploy as is). Constructor argument: `min_window_seconds` (use `60` for testing, `3600` for production).

| Method | Who | Purpose |
|---|---|---|
| `attest(owner, repo, commit_sha, spdx_id, license_path, manifest_path, bond_gen, challenge_window_seconds)` payable | attester | lock `bond_gen` GEN (2-1000, exact value) behind a certificate request; invalid input is refunded to the caller's balance, not reverted. `manifest_path` may be empty |
| `verify(attestation_id)` | anyone | consensus verification of the pinned files |
| `challenge_attestation(attestation_id, counter_path)` payable, same GEN as the attester bond | anyone but the attester | contest a `COMPLIANT_PROPOSED` attestation with another file from the same commit; at most 5 challenges per attestation, each with a new file. A counter file that cannot be fetched forfeits the challenge bond |
| `resolve_challenge(attestation_id)` | anyone | consensus re-judgment with the counter-evidence file |
| `cancel_challenge(attestation_id)` | anyone | refund a challenge that stayed unresolved for 3 days |
| `finalize(attestation_id)` | anyone | after the challenge window, mark the attestation `CERTIFIED` and release the attester bond |
| `expire_attestation(attestation_id)` | anyone | release a request stuck in verification for 3 days |
| `withdraw()` | anyone | pull payment of the caller's balance |

Registry views for other contracts: `is_certified(owner, repo, commit_sha, spdx_id) -> bool`, `get_status(...) -> str`, `get_certificate(...) -> JSON`, `list_certified()`.

Other views (JSON strings): `get_params`, `get_stats`, `list_attestations`, `get_attestation`, `list_attestations_by`, `get_balance`, `get_accounting`.

Supported SPDX identifiers: `MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `GPL-2.0-only`, `GPL-3.0-only`, `LGPL-3.0-only`, `AGPL-3.0-only`, `MPL-2.0`, `Unlicense`, `CC0-1.0`, `BSL-1.0`.

### Reading the registry from another contract

```python
registry = gl.get_contract_at(Address("ADDRESS"))
ok = registry.view().is_certified("Mary1270", "LicenseLedger", "FULL_40_CHAR_SHA", "MIT")
```

## Deployment

Deployed on GenLayer Studio at `ADDRESS`. The contract is submitted on its own; there is no frontend in this repository. The files under `evidence/` are sample inputs for live testing: pin them by the full SHA of the commit that contains them, for example `https://raw.githubusercontent.com/Mary1270/LicenseLedger/FULL_40_CHAR_SHA/LICENSE`.

## Tests

```
python3 -m unittest discover -s tests -p "test_*.py"
```

No pip install is needed. The suite runs against a small offline stand-in for the GenLayer SDK (`tests/genlayer_stub.py`). After every call it checks that the contract's real GEN balance equals its recorded obligations, and a seeded random walk finishes by draining every attestation to a terminal state and withdrawing everything to zero.

See `ARCHITECTURE.md` for the state machine, accounting and trust assumptions.

## License

MIT
