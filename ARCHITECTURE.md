# LicenseLedger architecture

## Entities

- **Attestation**: attester, owner, repo, full commit SHA, declared SPDX id, license path, optional manifest path, bond, challenge window, verdict fields, challenge history. Ids are `a1`, `a2`, ...
- **Certificate key**: `owner/repo@sha:spdx`, lower-cased. Only one live attestation exists per key. A key can be attested again only after its latest attestation ended `REJECTED`. `REVOKED` is permanent for the key: the files at a pinned SHA never change, so a conflict proven once stays proven, and a plain re-verification would not see the challenger's file. One commit can hold several certificates for different SPDX ids (for example a dual-licensed repository).
- **Registry**: the `latest` map from key to attestation id plus the `certified_ids` list. Other contracts read it through `is_certified`, `get_status` and `get_certificate`.

## Attestation state machine

```
attest -> PENDING                      (bond locked)
PENDING --verify COMPLIANT--> COMPLIANT_PROPOSED     (challenge_end = now + window)
PENDING --verify NON_COMPLIANT--> REJECTED           (bond refunded)
PENDING --verify UNDETERMINED--> PENDING             (attempts+1; 3rd attempt -> REJECTED, bond refunded)
PENDING --stale 3 days, expire_attestation--> REJECTED (bond refunded)
COMPLIANT_PROPOSED --challenge_attestation (before challenge_end, max 5)--> CHALLENGED
COMPLIANT_PROPOSED --finalize after challenge_end--> CERTIFIED (bond refunded, registry entry)
CHALLENGED --resolve NON_COMPLIANT--> REVOKED        (challenger gets both bonds, key closed for good)
CHALLENGED --resolve COMPLIANT--> COMPLIANT_PROPOSED (attester gets the challenger bond)
CHALLENGED --resolve COUNTER_MISSING--> COMPLIANT_PROPOSED (counter file not fetchable, attester gets the challenger bond)
CHALLENGED --resolve UNDETERMINED--> COMPLIANT_PROPOSED (challenger bond refunded)
CHALLENGED --stale 3 days, cancel_challenge--> COMPLIANT_PROPOSED (challenger bond refunded)
```

After a challenge that does not revoke, the window becomes `max(old challenge_end, now + min_window)` while a challenge slot remains, and `max(old challenge_end, now)` after the last slot. The window is never shortened, so an attester cannot burn the challenge slots with a second wallet to finalize early. A counter file that cannot be fetched counts as a failed challenge, so slots cannot be used up for free with paths that do not exist. Every state has a way to a terminal state that needs no cooperation from any single party, so no bond can stay locked forever.

## Verification

`_evaluate` runs identically on the leader and every validator:

1. Fetch the `LICENSE` file at the pinned URL. A failed fetch is `UNDETERMINED`.
2. License anchor: the normalised text must contain every marker phrase of the declared SPDX license, must not contain any forbidden phrase (BSD-2-Clause rejects the third clause), and for the GPL family the title must lead the file. Otherwise `NON_COMPLIANT` with no model call. During a challenge this check can only produce `UNDETERMINED`, because the same file already passed it at verification and a challenge must be decided on the counter-evidence.
3. Fetch the manifest and, for a challenge, the counter-evidence file. A failed manifest fetch is `UNDETERMINED`; a failed counter-evidence fetch is `COUNTER_MISSING`, which rejects the challenge.
4. Ask the model for `{verdict, license_quote, manifest_quote, conflict_quote, reason}`. All file text is declared untrusted in the prompt.
5. Grounding in code: `COMPLIANT` needs a `license_quote` of at least 12 characters that occurs in the `LICENSE` text after whitespace normalisation, and with a manifest also needs the manifest to declare the SPDX id as a whole token (or a listed alias such as `Apache License, Version 2.0`) and a `manifest_quote` that occurs in the manifest. `NON_COMPLIANT` needs a `conflict_quote` of at least 12 characters that occurs in the counter-evidence file (or in the license and manifest when there is no challenge). Anything else becomes `UNDETERMINED`.

Consensus uses `gl.vm.run_nondet_unsafe(leader, validator)` created by a module-level function, so no contract `self` is captured. The validator re-derives its own verdict and requires the same categorical verdict as the leader; quotes and reason are leader-attested. All errors are caught inside the nondet closures and turned into ordinary `UNDETERMINED` strings.

## Pinned URL rules

The attester supplies parts, never a URL. `owner` must be a valid GitHub account name, `repo` a valid repository name, `commit_sha` exactly 40 hex characters (lower-cased, not all zero), and each path made of segments from `A-Z a-z 0-9 . _ -` with no empty or all-dot segment, at most 200 characters. The URL is assembled as `https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}` and parsed again: scheme, exact host, no credentials, no port, no query, no fragment and an unchanged path. A counter-evidence path must be a file that is not the license file, not the manifest and not used by an earlier challenge on the same attestation.

## Money

All amounts are wei internally; users enter whole GEN (`bond_gen`, payable value). The attached value must equal `bond_gen` exactly, and a challenge must attach the same amount as the attester bond. Payouts are pull-based: every outcome only credits `balances`, and `withdraw` transfers. Payable methods never revert on bad input; they credit the attached value back to the caller's balance. Invariant checked in tests after every call:

```
contract balance == sum(attester locked + challenger locked) + sum(balances)
```

`get_accounting` exposes both sides and the separately kept `total_bonds` counter.

## Trust assumptions and known limits

- **Fork commits.** GitHub serves a commit that exists only in a fork under the parent repository's raw path. A certificate therefore attests the content found at that SHA under `owner/repo`; consumers should treat the 40-character SHA as the identity and prefer SHAs they know belong to the repository's own history.
- **Hostile file text.** A file can contain instructions aimed at the model. Code anchors, whole-token manifest checks and exact quotes limit the damage, and every validator judges independently, but a malicious counter-evidence file written by a challenger is still evidence the model reads.
- **License text only.** The `LICENSE` text alone cannot tell `GPL-3.0-only` from `GPL-3.0-or-later`; attest with a manifest to pin that distinction. A `LICENSE` file with a notice placed before a GPL-family title is treated as non-matching.
- **Scope.** The certificate covers the declared `LICENSE` file, the optional manifest and challenger-cited files. It is not a full dependency or per-file header audit.
- Time comes from `datetime.datetime.now()` as seen by GenVM.
- At most 5 challenges per attestation, each with a new file, and a certificate is final once finalized. A challenger with an honest but unclear file pays nothing when the result is `UNDETERMINED`, so a determined party with several wallets can still use up the slots with real but irrelevant files that the model cannot decide on; the slot limit and the never-shortened window bound that, they do not remove it.
