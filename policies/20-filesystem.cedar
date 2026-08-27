// 20-filesystem.cedar — reads and writes over path-shaped arguments.
//
// The workspace boundary is the organising idea: inside it, reads are ordinary;
// outside it, they are worth a second look; writes are worth a human either way.
// `pathsWithinWorkspace` is computed after path resolution, so `..` segments and
// symlink targets are accounted for before policy sees the answer.

// ─── Reads ───────────────────────────────────────────────────────────────────

@id("fs_read_within_workspace")
@sentinel_obligation("allow")
@sentinel_reason("Read-only tool operating entirely inside the workspace.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"read_only"
) when {
    context.pathsWithinWorkspace &&
    !context.hasParentTraversal &&
    context.toolScanVerdict == "clean"
};

// Outside the workspace, or with a literal `..` in the request. Neither is
// necessarily an attack — plenty of legitimate calls read a system config — but
// neither is routine, so it gets scored rather than waved through.
@id("fs_read_outside_workspace")
@sentinel_obligation("review")
@sentinel_reason("Read-only tool reaching outside the workspace, or using parent traversal.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"read_only"
) when {
    !context.pathsWithinWorkspace || context.hasParentTraversal
};

// A tool whose definition merely looks suspicious is still callable, but every
// call is scored. Blocking outright on "suspicious" would make the scanner's
// false positives indistinguishable from its true ones.
@id("fs_read_suspicious_tool")
@sentinel_obligation("review")
@sentinel_reason("The tool definition was flagged as suspicious by the scanner.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"read_only"
) when {
    context.toolScanVerdict == "suspicious"
};

// ─── Writes ──────────────────────────────────────────────────────────────────

// Mutation inside the workspace by a trusted agent: still a human decision, but
// this is the case where an operator might reasonably relax to "review" once
// they trust their policy set. Left at "approve" as the safe default.
@id("fs_write_within_workspace")
@sentinel_obligation("approve")
@sentinel_reason("Mutating tool inside the workspace requires human approval.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"mutating"
) when {
    context.pathsWithinWorkspace &&
    !context.hasParentTraversal &&
    principal.trustTier == "trusted"
};

// Standard-tier agents writing inside the workspace. Same obligation, separate
// policy id so the audit trail records *which* grant applied — "approved under
// the standard-tier rule" and "approved under the trusted-tier rule" are
// different facts about a decision.
@id("fs_write_standard_tier")
@sentinel_obligation("approve")
@sentinel_reason("Mutating tool called by a standard-tier agent requires human approval.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"mutating"
) when {
    context.pathsWithinWorkspace &&
    !context.hasParentTraversal &&
    principal.trustTier == "standard"
};

// ─── Resource reads ──────────────────────────────────────────────────────────

@id("fs_resource_read_within_workspace")
@sentinel_obligation("allow")
@sentinel_reason("Resource read inside the workspace over a local scheme.")
permit (
    principal,
    action == Sentinel::Action::"readResource",
    resource
) when {
    context.pathsWithinWorkspace &&
    context.scheme == "file" &&
    !context.hasExternalUrl
};

@id("fs_resource_read_remote")
@sentinel_obligation("review")
@sentinel_reason("Resource read over a non-local scheme, or reaching outside the workspace.")
permit (
    principal,
    action == Sentinel::Action::"readResource",
    resource
) when {
    context.scheme != "file" || !context.pathsWithinWorkspace
};
