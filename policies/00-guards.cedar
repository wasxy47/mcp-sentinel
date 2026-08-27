// 00-guards.cedar — unconditional refusals.
//
// `forbid` overrides every `permit` in Cedar, so these are the invariants no
// policy elsewhere in the bundle can loosen. Keep this file small and keep every
// rule here genuinely absolute: a forbid that needs an exception belongs in the
// permit files as a narrower grant instead.

// ─────────────────────────────────────────────────────────────────────────────
// Quarantined servers are off entirely.
//
// Quarantine is what the scanner or an operator applies to a server believed
// hostile. Not "score it more carefully" — off.
// threat-model.md T1, T3
// ─────────────────────────────────────────────────────────────────────────────
@id("guard_quarantined_server_tools")
@sentinel_reason("The server providing this tool is quarantined.")
forbid (
    principal,
    action == Sentinel::Action::"callTool",
    resource
) when {
    resource.server.trust == "quarantined"
};

@id("guard_quarantined_server_resources")
@sentinel_reason("The server providing this resource is quarantined.")
forbid (
    principal,
    action == Sentinel::Action::"readResource",
    resource
) when {
    resource.server.trust == "quarantined"
};

@id("guard_quarantined_server_prompts")
@sentinel_reason("The server providing this prompt is quarantined.")
forbid (
    principal,
    action == Sentinel::Action::"getPrompt",
    resource
) when {
    resource.server.trust == "quarantined"
};

// ─────────────────────────────────────────────────────────────────────────────
// A tool the scanner judged malicious is never callable.
//
// Note this is checked on the TOOL, not the arguments. A poisoned description
// has already done its damage by the time the agent constructs a call — the
// model read it. Refusing the call limits the blast radius; it does not undo
// the injection. That is why detection is layered with argument-level policy
// rather than relied upon alone.
// threat-model.md T1
// ─────────────────────────────────────────────────────────────────────────────
@id("guard_malicious_tool")
@sentinel_reason("This tool's definition was flagged as malicious by the scanner.")
forbid (
    principal,
    action == Sentinel::Action::"callTool",
    resource
) when {
    resource.scanVerdict == "malicious"
};

// ─────────────────────────────────────────────────────────────────────────────
// Rug pull: the definition changed since it was last approved.
//
// Nothing in MCP pins a tool definition, so a server can serve a benign
// description during review and a poisoned one afterwards. Drift is therefore
// treated as hostile until an operator re-approves, rather than as a routine
// version bump.
// threat-model.md T3
// ─────────────────────────────────────────────────────────────────────────────
@id("guard_definition_drift")
@sentinel_reason("This tool's definition changed since it was last approved.")
forbid (
    principal,
    action == Sentinel::Action::"callTool",
    resource
) when {
    resource.definitionDrifted
};

// ─────────────────────────────────────────────────────────────────────────────
// Never hand credentials to an untrusted server.
//
// The single highest-value exfiltration primitive: the agent is persuaded to
// pass a token it legitimately holds to a server that has no business seeing it.
// No obligation, no approval prompt — a human asked to approve this at 2am is a
// human who will approve it.
// threat-model.md T1, T11
// ─────────────────────────────────────────────────────────────────────────────
@id("guard_credential_to_untrusted_server")
@sentinel_reason("The arguments contain credential-shaped values and the target server is not trusted.")
forbid (
    principal,
    action == Sentinel::Action::"callTool",
    resource
) when {
    context.containsCredential && context.serverTrust != "trusted"
};

// ─────────────────────────────────────────────────────────────────────────────
// Never send credentials to a host outside the allowlist.
//
// The rule above covers an untrusted *server*. This one covers the other half of
// the same attack: a perfectly trusted fetch tool, pointed by attacker-chosen
// arguments at an attacker-controlled host, with a token in the body. The tool is
// trusted; the destination is not. Both halves are needed, because trusting the
// server says nothing about where the server was told to go.
// threat-model.md T8
// ─────────────────────────────────────────────────────────────────────────────
@id("guard_credential_to_external_url")
@sentinel_reason("The arguments contain credential-shaped values and reference a host outside the allowlist.")
forbid (
    principal,
    action == Sentinel::Action::"callTool",
    resource
) when {
    context.containsCredential && context.hasExternalUrl
};

// ─────────────────────────────────────────────────────────────────────────────
// Known-sensitive locations are never readable through the gateway.
//
// ~/.ssh, ~/.aws, .env, private key files. An agent has no legitimate reason to
// read these through a tool call, and every prompt-injection exfiltration chain
// wants to.
// threat-model.md T1, T8
// ─────────────────────────────────────────────────────────────────────────────
@id("guard_sensitive_path_tool")
@sentinel_reason("The arguments reference a known-sensitive path (credentials, keys, or environment files).")
forbid (
    principal,
    action == Sentinel::Action::"callTool",
    resource
) when {
    context.hasSensitivePath
};

@id("guard_sensitive_path_resource")
@sentinel_reason("The resource URI references a known-sensitive path.")
forbid (
    principal,
    action == Sentinel::Action::"readResource",
    resource
) when {
    context.hasSensitivePath
};

// ─────────────────────────────────────────────────────────────────────────────
// Invisible Unicode in arguments.
//
// Zero-width, bidi-override and tag characters have no legitimate place in a
// tool argument. Their presence means something is trying to make the rendered
// text differ from the interpreted text — of the argument, or of the audit
// record a human will later read.
// threat-model.md T2
// ─────────────────────────────────────────────────────────────────────────────
@id("guard_invisible_unicode")
@sentinel_reason("The arguments contain invisible or direction-overriding Unicode characters.")
forbid (
    principal,
    action == Sentinel::Action::"callTool",
    resource
) when {
    context.hasInvisibleUnicode
};

// ─────────────────────────────────────────────────────────────────────────────
// A critical risk score is final.
//
// Present only on the second pass, after the risk engine has scored the call.
// Above this line there is nothing left to escalate to.
// ─────────────────────────────────────────────────────────────────────────────
@id("guard_critical_risk_score")
@sentinel_reason("The risk engine scored this call as critical.")
forbid (
    principal,
    action == Sentinel::Action::"callTool",
    resource
) when {
    context has riskScore && context.riskScore >= 90
};

// ─────────────────────────────────────────────────────────────────────────────
// Untrusted agents cannot mutate anything, at any risk score, with any approval.
//
// The `untrusted` tier exists for agents running attacker-adjacent workloads —
// summarising inbound email, processing public issues. Read access is the whole
// point; write access is not on the table.
// threat-model.md T21
// ─────────────────────────────────────────────────────────────────────────────
@id("guard_untrusted_agent_mutation")
@sentinel_reason("Agents in the untrusted tier may not call mutating tools.")
forbid (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"mutating"
) when {
    principal.trustTier == "untrusted"
};
