# MEVA Reviewer Handbook

## Purpose and authority

This handbook defines the general assurance method for backend, AI/agent, data,
platform, and embodied projects. Reviewers must also follow `AGENTS.md`. Field
shapes and canonical tokens come only from `contracts/meva.schema.json`; this
handbook explains their meaning and must not be used to create aliases.

Review is independent, read-only, evidence based, and consequence focused. A
Reviewer with material authorship overlap or without runtime-owned proof of its
read-only boundary cannot issue a valid gate result. Any mutation or non-empty
`changed` invalidates the review and requires a new independent Reviewer.
An explicitly advisory review emits no gate. A formal review without current
runtime-owned identity, nonempty current artifact and evidence targets,
effective read-only enforcement, and independence proof fails closed. External
reads require an exact target/read-only effect, a reservation of at least one
call, and a single-use claim; mutation invalidates the review.

## Review procedure

1. Establish the exact ticket, state and invalidation revisions, requirements,
   non-goals, consequence-based risk, review scope, exclusions, and applicable
   gates.
2. Verify provenance and artifact digests, effective permission attestation,
   independence, validation methods/results, and any trusted approval records.
3. Trace the implemented path and its failure paths: inputs, authorization,
   state, concurrency, persistence, integrations, resource/action bounds,
   observability, recovery, and shutdown.
4. Map every accepted requirement to evidence and a schema-valid result. Missing,
   stale, invalidated, or non-reproducible evidence is `unverified`, never pass.
5. Record each concrete defect as a finding with severity, independent
   remediation priority, category, disposition, gate impact, narrow evidence,
   consequence, credible trigger, owner, and required action.
6. Check that duplicate, withdrawn, resolved, and risk-accepted dispositions
   retain the original evidence and required rationale.
7. Evaluate gates without consulting remediation priority, then issue exactly
   one schema-valid recommendation.

## Finding record

A useful finding answers:

- **What is wrong?** A specific violated requirement, unsafe behavior, evidence
  defect, or credible regression—not a style preference.
- **Where is it?** The narrowest artifact, symbol, interface, evidence ID, state
  revision, or reproducible procedure.
- **How does it trigger?** Preconditions, inputs, environment, concurrency,
  dependency failure, attacker capability, or operational event.
- **What happens?** User, system, data, safety, security, cost, or operational
  consequence and blast radius.
- **Why this severity?** Consequence plus credible reachability/likelihood.
- **What closes it?** A bounded remediation or verification with an owner and
  inspectable evidence.
- **What gate does it affect?** The earliest gate whose exit claim is false and
  every dependent gate invalidated by it.

Use one finding per independently remediable root cause. Link correlated effects
rather than duplicating them. Uncertainty does not erase a finding: state the
unknown and give a bounded reproduction or evidence request.

## Severity: consequence and likelihood

Severity determines risk and blocking. It does not measure repair effort,
schedule pressure, seniority, or how soon a team wants to work on it.

| Severity | Meaning | Required gate behavior |
|---|---|---|
| `critical` | A credible condition can cause catastrophic physical harm, uncontrolled production action, broad compromise, irreversible/catastrophic data loss, or similarly existential impact; or such harm is active/imminent. | Stop affected execution immediately. It is always P0 and blocks dependent gates/release until resolved or exact authorized human risk acceptance is verified where acceptance is legally and contractually permitted. |
| `high` | A credible trigger causes serious correctness, security, privacy, safety, data-integrity, financial, or operational harm with material blast radius. | Blocks release and any gate whose exit claim it disproves. It is P0 or P1. Only exact trusted human risk acceptance can disposition it; Reviewer cannot waive it. |
| `medium` | A material defect or assurance gap has bounded consequence, constrained reachability, or a viable containment; it is not merely cosmetic. | Does not automatically block release, but may block the affected gate when its stated exit criterion is unmet. Resolve or record an owned, time-bounded disposition. |
| `low` | A limited non-blocking defect or maintainability/operability improvement has concrete value and negligible immediate consequence. | Track with an owner or rationale; it blocks only when an explicit accepted criterion says so. |

Assess the worst credible outcome under accepted operating assumptions, then
adjust for demonstrated reachability and controls. Do not lower severity merely
because detection is likely, remediation is easy, a feature is new, tests are
green, or a deadline is close. Do not inflate severity from hypothetical chains
without a plausible trigger.

Open critical and high findings remain blocking regardless of priority.

## Remediation priority P0-P3

Priority orders remediation work; it never changes severity, disposition,
approval requirements, recommendation, or blocking.

| Priority | Scheduling meaning | Typical use |
|---|---|---|
| `P0` | Act now; stop affected work or restore a required control before other dependent work. | Every critical; high with active exploitation, unsafe execution, broad exposure, or critical-path gate failure. |
| `P1` | Resolve before the affected release/gate proceeds. | High without active incident; urgent medium that directly invalidates an acceptance criterion. |
| `P2` | Schedule in the next bounded maintenance or delivery window. | Most contained medium findings and unusually valuable low-risk corrections. |
| `P3` | Backlog and review through normal prioritization. | Low findings with concrete but non-urgent value. |

Changing P0 to P3 cannot make a high finding non-blocking. Conversely, assigning
P0 to a medium finding does not make it high; it only expresses sequencing.

## Categories

Choose the single schema category representing the finding's primary failed
property. Mention secondary impacts in the finding body rather than creating
aliases.

| Category | Primary concern |
|---|---|
| `correctness` | Required behavior, contracts, state transitions, edge cases, or regressions |
| `security` | Authorization, isolation, injection, exploitation, secrets, or excessive privilege |
| `privacy` | Collection, consent, use, disclosure, retention, residency, or subject rights |
| `safety` | Physical or consequential autonomous hazards and required controls |
| `data_integrity` | Corruption, loss, lineage, consistency, migration, or reconciliation |
| `reliability` | Availability, failure containment, retry/idempotency, concurrency, or recovery |
| `performance` | Latency, throughput, memory, capacity, or scaling against an accepted target |
| `cost` | Spend bounds, metering, runaway use, quota, or resource lifecycle |
| `architecture` | Ownership/interface boundaries, dependency direction, evolvability, or systemic coupling |
| `maintainability` | Concrete change risk, diagnosability, complexity, or support burden |
| `operations` | Deployment, monitoring, incident response, rollback, teardown, or runbooks |
| `evaluation_validity` | Metrics, thresholds, leakage, sampling, statistics, reproducibility, or test claims |
| `requirement_traceability` | Missing, ambiguous, or stale mapping from requirement to evidence |
| `supply_chain` | Dependency provenance, integrity, licensing, build inputs, or artifact trust |
| `compliance` | Applicable legal, regulatory, contractual, or policy obligation |
| `other` | A concrete issue that fits none of the defined categories; explain why |

## Dispositions

- `open`: the finding remains true and its required closure evidence is absent.
- `resolved`: current evidence proves the defect was fixed or the false claim was
  removed, and every affected invalidated check was rerun. Critical/high RV2
  resolution evidence must bind the current state and invalidation revision,
  cover the exact finding trigger, required action, artifacts, and environment,
  carry provenance, and be authored independently of the finding/remediation
  owner and affected artifact authors. Every covered artifact must exist and be
  current.
- `risk_accepted`: the defect remains, but a trusted approval resolver verifies
  the exact finding revision, `risk_accept_finding` action, structured affected
  operation, scope, environment, limits, status, issuance, and unexpired UTC
  expiry. Reviewer records the approval ID but does not grant acceptance.
  Critical safety findings and required emergency-stop, deterministic-safety,
  or live embodied controls cannot use this disposition regardless of a
  self-declared `waivable` field. Corresponding approval limits may be narrower
  than the affected operation but never broader or mismatched.
  Legacy extension-empty critical/high acceptance is diagnostic only and cannot
  close a formal gate.
- `duplicate`: another finding owns the same root cause and remediation. Retain
  the original evidence, identify the canonical finding, and record why the
  issues are equivalent.
- `withdrawn`: new evidence proves the original claim was incorrect or outside
  accepted scope. Retain the original evidence and record the reason and the new
  disconfirming evidence. Disagreement, cost, or lateness is not a reason.

`not_applicable` is reserved for requirement or gate applicability, not finding
disposition. A resolved, duplicate, withdrawn, or risk-accepted finding is never
deleted. Disposition changes are revisioned and inspectable. Revocation or
expiry returns a risk-accepted blocker to `open`.

## Gate mapping and recommendations

Map each finding to the earliest lifecycle exit condition it falsifies.

A transitive dependency on a false exit condition is invalidated even if its own
artifact did not change.

Resolved invalidation closure requires all affected artifacts current, all
affected evidence current and passing at the exact invalidation revision, all
affected gates passing at that revision with nonempty current passing evidence,
and no explicitly affected task left blocked. Closure analysis includes tasks,
approvals, permission attestations, persistent resources, findings, and
provenance nodes as well as requirements, interfaces, artifacts, evidence, and
gates. Resolved behavior-affecting provenance changes require nonempty affected
evidence and gates.

Gate evaluation ignores P0-P3:

- `pass`: all required evidence is current, all applicable criteria pass, and no
  open blocking finding remains.
- `conditional`: no open critical/high finding remains, and bounded medium/low
  conditions have explicit owners, actions, deadlines/expiry where applicable,
  and do not contradict the gate's mandatory exit criteria.
- `fail`: any open critical/high finding exists; required independence or trusted
  approval is invalid; a mandatory criterion fails; or required evidence cannot
  support advancement.

A formal pass also requires a supported explicit review mode, current exact
runtime-owned Reviewer activation, and an independent-review gate whose owner,
recommendation, current revisions, and non-implementation-authored evidence all
agree. Advisory or legacy diagnostic output never emits that gate.

Use `unverified` for a gate/result when required evidence is missing or stale.
Do not disguise it as `conditional`. The final Reviewer recommendation uses only
`pass`, `conditional`, or `fail`; explain any unverified inputs in findings or
evidence gaps and select the recommendation required by the affected gate.

## Evidence standards

Evidence must identify the exact artifact/revision, procedure, environment,
inputs, expected result, observed result, and provenance needed to reproduce the
claim. Prefer the narrowest deterministic reproduction. Redact secrets and
restricted content without destroying the proof.

These are insufficient alone:

- author assertion or architectural intent;
- a green test that does not exercise the changed failure path;
- static configuration as proof of effective runtime permissions;
- lower-environment evidence as production or `controlled_hardware` proof;
- an approval ID without trusted exact-match verification;
- stale evidence from before an invalidating requirement/interface/input change.
