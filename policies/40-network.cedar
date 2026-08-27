// 40-network.cedar — outbound requests.
//
// Egress is the exfiltration channel. Every prompt-injection chain that wants to
// *steal* something rather than merely destroy it ends at a tool that can reach
// the network, so the deciding feature here is not "is this a network tool" but
// "where is it pointing, and how much is going with it".
//
// `hasExternalUrl` is computed against the operator's host allowlist, so
// "external" means "not on the list", not "not on the LAN". A permissive
// allowlist makes these policies permissive; that is the operator's dial.

// ─── Fetching ────────────────────────────────────────────────────────────────

@id("net_fetch_allowlisted_host")
@sentinel_obligation("allow")
@sentinel_reason("Outbound request to an allowlisted host.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"network"
) when {
    context.hasUrl &&
    !context.hasExternalUrl &&
    !context.containsCredential &&
    context.toolScanVerdict == "clean"
};

@id("net_fetch_external_host")
@sentinel_obligation("review")
@sentinel_reason("Outbound request to a host outside the allowlist.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"network"
) when {
    context.hasUrl && context.hasExternalUrl
};

// A network tool invoked with no URL-shaped argument is not obviously safe — it
// may be carrying a destination in a field the extractor did not recognise as a
// URL. Absence of evidence is not evidence here, so it is scored.
@id("net_no_url_argument")
@sentinel_obligation("review")
@sentinel_reason("Network-capable tool called with no recognisable URL argument.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"network"
) when {
    !context.hasUrl
};

// ─── Sending ─────────────────────────────────────────────────────────────────

// Tools that carry a payload outbound — post, upload, send_email, webhook.
// Destination inside the allowlist is still a human decision at the boundary of
// the trust domain, because the allowlist bounds *where*, not *what*.
@id("net_send_allowlisted_host")
@sentinel_obligation("approve")
@sentinel_reason("Payload-carrying tool sending to an allowlisted host.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"exfiltration_capable"
) when {
    !context.hasExternalUrl
};

@id("net_send_external_host")
@sentinel_obligation("approve")
@sentinel_reason("Payload-carrying tool sending to a host outside the allowlist.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"exfiltration_capable"
) when {
    context.hasExternalUrl &&
    principal.trustTier == "trusted"
};

// Volume is its own signal. A 64 KiB argument on an outbound call is not a
// parameter, it is a payload — the shape of "read the file, then post it
// somewhere" collapsed into one call.
// threat-model.md T8
@id("net_bulk_outbound_payload")
@sentinel_obligation("approve")
@sentinel_reason("Large argument payload on an outbound request; possible bulk exfiltration.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"network"
) when {
    context.argBytes > 65536 &&
    context.hasUrl
};
