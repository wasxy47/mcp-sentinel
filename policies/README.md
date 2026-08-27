# Policy bundle

Cedar schema and policies. This directory is data, not code — the gateway loads
it at startup and reloads it on change, and nothing here is compiled.

```
schema.cedarschema    entity, action and context shapes
00-guards.cedar       forbid rules — unconditional refusals
10-catalog.cedar      discovery and listing
20-filesystem.cedar   path-shaped arguments
30-database.cedar     SQL-shaped arguments
40-network.cedar      outbound requests
45-shell.cedar        command execution
50-governance.cedar   Sentinel's own tools
```

Validate the whole bundle:

```bash
npm run policy:lint
```

The linter is the gate: it fails on a parse error, a missing or duplicated `@id`,
a permit without a valid `@sentinel_obligation`, a forbid that carries one, a
missing `@sentinel_reason`, or any strict-mode validation error **or warning**.

## Why files are numbered

Load order does not affect the decision — Cedar is order-independent, and
`forbid` always beats `permit` regardless of where either sits. The numbers are
for humans: they put the absolute rules first so that reading the bundle
top-to-bottom reads as "here is what is never allowed, and here is what is
allowed under which conditions".

The gap between `40` and `45` is deliberate room, not an accident.

## The two annotations that matter

Cedar answers `allow` or `deny`. Sentinel needs four outcomes — allow, review,
approve, deny — so each `permit` carries the ceremony its grant requires:

```cedar
@id("fs_write_within_workspace")
@sentinel_obligation("approve")
@sentinel_reason("Mutating tool inside the workspace requires human approval.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"mutating"
) when { ... };
```

* **`@id`** — the stable name of this rule. It is what appears in
  `diagnostics.reason`, in the audit record, and in `explain_decision`.
* **`@sentinel_obligation`** — `allow` | `review` | `approve`. When several
  permits match, the strongest obligation wins, mirroring Cedar's own
  forbid-overrides-permit conservatism.
* **`@sentinel_reason`** — the sentence a human reads in the approval prompt and
  in the audit trail. Write it for that reader, not for the policy author.

`forbid` policies take `@id` and `@sentinel_reason` but never an obligation: a
refusal that could be softened by ceremony is not a refusal.

### `@id` is load-bearing

Cedar assigns positional ids — `policy0`, `policy1`, … — when a policy set is
handed over as a single blob of text, and those are the ids that come back in
`diagnostics.reason`:

```
record-keyed  { decision: "allow", reason: ["fs_read_within_workspace"] }
text-blob     { decision: "allow", reason: ["policy16"] }
```

Positional ids shift the moment a policy is inserted anywhere above, which would
silently re-point every previously recorded decision at the wrong rule. So the
loader splits each file into individual policies, reads the `@id` annotation, and
hands Cedar a policy set keyed by those ids. `npm run policy:lint` is what
guarantees the keys exist and are unique.

## Writing a new policy

1. **Prefer a narrower permit over an exception to a forbid.** If a `forbid` in
   `00-guards.cedar` needs a carve-out, the carve-out belongs in a permit file as
   a more specific grant. The guard file only holds rules that are genuinely
   absolute.

2. **Constrain the context, not just the tool.** Tool-level allow/deny is too
   coarse to be useful: `execute_sql` is fine and `DROP TABLE users` is not.
   Every field in `ToolCallContext` is extracted by static inspection of the
   arguments, with no model in the loop, so policies stay reproducible.

3. **Give distinct grants distinct ids even when the obligation matches.**
   `fs_write_within_workspace` and `fs_write_standard_tier` both resolve to
   `approve`. Keeping them separate means the audit trail records *which* grant
   applied, and "approved under the trusted-tier rule" is a different fact from
   "approved under the standard-tier rule".

4. **Remember that absence of a permit is a denial.** Several deliberate denials
   in this bundle are expressed by simply not granting the case — a standard-tier
   agent chaining shell commands, an untrusted-tier agent running any command at
   all. Prefer that to a forbid when the rule is "not this combination" rather
   than "never, under any policy".

5. **Treat "unknown" as risk, not as absence.** `sqlKind == "unknown"` means the
   parser failed, which is either exotic-but-fine SQL or an injection attempt.
   Policies here escalate it.

## Groups

`ToolGroup` membership is assigned by operator configuration, not inferred from
tool names, and a tool may belong to several groups. The bundle currently expects:

| Group                    | Meaning                                       |
| ------------------------ | --------------------------------------------- |
| `read_only`              | cannot modify anything                        |
| `mutating`               | writes, creates or deletes                    |
| `database`               | takes SQL-shaped arguments                    |
| `network`                | makes outbound requests                       |
| `exfiltration_capable`   | carries a payload outbound                    |
| `shell`                  | executes commands                             |

`AgentGroup` membership is likewise operator-assigned: `auditors` may read the
audit trail, `approvers` may resolve pending approvals. Neither is ever derived
from `clientInfo`, which is an unverified assertion by the caller.

See [`../docs/architecture.md`](../docs/architecture.md) § 4.1–4.2 for why Cedar,
and how four outcomes are modelled on a two-valued engine.
