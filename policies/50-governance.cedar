// 50-governance.cedar — Sentinel's own tools.
//
// Sentinel exposes governance tools of its own (`explain_decision`,
// `query_audit_log`, `list_active_policies`, `verify_audit_chain`,
// `approve_request`). Those tools are subject to the same engine as everything
// else — a governance surface that exempts itself from its own policy is not a
// governance surface.
//
// The asymmetry to notice: explanation and policy listing are deliberately open,
// because an agent that can see why it was denied can correct itself instead of
// retrying blindly, and that reduces load on the approval channel. Reading the
// audit trail is not open, because the trail contains other agents' arguments.
// Approving is narrowest of all.

// ─── Open: self-explanation and policy transparency ──────────────────────────

// An agent may ask why *a* decision went the way it did. The tool implementation
// scopes results to decisions belonging to the calling agent; policy grants the
// capability, the tool enforces the row-level scope. Both layers are needed —
// Cedar cannot see which rows a query will touch.
@id("gov_explain_decision")
@sentinel_obligation("allow")
@sentinel_reason("Agents may retrieve the explanation for their own decisions.")
permit (
    principal,
    action == Sentinel::Action::"explainDecision",
    resource == Sentinel::Endpoint::"gateway"
);

// Listing active policies reveals the rules, not the data. Publishing the rules
// is the correct default for a governance gateway: a caller that knows the
// boundary stops probing it, and a boundary whose secrecy is load-bearing is a
// boundary that was never enforced.
@id("gov_list_active_policies")
@sentinel_obligation("allow")
@sentinel_reason("The active policy set is not confidential.")
permit (
    principal,
    action == Sentinel::Action::"listActivePolicies",
    resource == Sentinel::Endpoint::"gateway"
);

// ─── Restricted: reading the trail ───────────────────────────────────────────

// The audit trail records every agent's arguments, redacted but still revealing.
// Querying it is an auditor capability, and it requires a verified identity —
// `authenticated` is false whenever the agent id came from an unverified header,
// and an unverified caller reading the audit log would be an information leak
// dressed as a feature.
// threat-model.md T11
@id("gov_query_audit_log")
@sentinel_obligation("allow")
@sentinel_reason("Auditor-group agents with a verified identity may query the audit trail.")
permit (
    principal in Sentinel::AgentGroup::"auditors",
    action == Sentinel::Action::"queryAuditLog",
    resource == Sentinel::Endpoint::"gateway"
) when {
    principal.authenticated
};

// Chain verification returns integrity status, not row contents, so it is a
// weaker capability than querying — but it is still the tool that would tell an
// attacker whether their tampering has been noticed yet.
// threat-model.md T10, T12
@id("gov_verify_audit_chain")
@sentinel_obligation("allow")
@sentinel_reason("Auditor-group agents with a verified identity may verify chain integrity.")
permit (
    principal in Sentinel::AgentGroup::"auditors",
    action == Sentinel::Action::"verifyAuditChain",
    resource == Sentinel::Endpoint::"gateway"
) when {
    principal.authenticated
};

// ─── Narrowest: approving ────────────────────────────────────────────────────

// `approve_request` exists so a human's MCP client can resolve a pending
// approval without leaving their agent session. It is emphatically NOT for
// agents: an agent that can approve its own escalations has converted the
// approval gate into a speed bump.
//
// Three independent controls stand behind this one permit, and the policy is the
// weakest of them:
//   1. this grant — approver group, verified identity, trusted tier;
//   2. the approval store rejects any decision whose approver identity matches
//      the requesting agent, so self-approval fails even if a policy is
//      misconfigured (M5.1);
//   3. the HMAC-signed loopback link is single-use and bound to one approval id,
//      so a captured link cannot be replayed against a different request (M5.2).
//
// Note there is no `@sentinel_obligation("approve")` here — requiring approval
// in order to approve is circular, and would deadlock the channel on its first
// use. This is the one place where "allow" is the strongest available answer,
// which is exactly why the grant is this narrow.
// threat-model.md T14
@id("gov_approve_request")
@sentinel_obligation("allow")
@sentinel_reason("Approver-group agents with a verified, trusted identity may resolve pending approvals.")
permit (
    principal in Sentinel::AgentGroup::"approvers",
    action == Sentinel::Action::"approveRequest",
    resource == Sentinel::Endpoint::"gateway"
) when {
    principal.authenticated &&
    principal.trustTier == "trusted"
};
