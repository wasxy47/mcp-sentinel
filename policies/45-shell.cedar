// 45-shell.cedar — command execution.
//
// A shell tool is a universal tool: it subsumes every other capability the host
// can reach, which makes tool-level classification useless and argument-level
// classification the only real control. Sentinel does not try to *understand*
// commands — a static analyser that claims to know what an arbitrary shell line
// does is lying. It classifies the command's structural shape and hands anything
// with room for chaining to a human.
//
// The absence of a permit is a denial. That is load-bearing here: the
// combinations not listed below — a standard-tier agent chaining commands, an
// untrusted-tier agent running anything at all — are denied by default rather
// than by an explicit forbid, so the guard file stays free of shell specifics.

@id("shell_trusted_simple_command")
@sentinel_obligation("approve")
@sentinel_reason("Single shell command with no chaining or redirection, from a trusted agent.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"shell"
) when {
    principal.trustTier == "trusted" &&
    !context.hasShellMetacharacters
};

// Pipes, semicolons, backticks, `$(...)`, redirections. Legitimate in ordinary
// use and also exactly how one benign-looking command becomes two. Same
// obligation as above but a distinct policy id, so the audit record says which
// grant applied — "approved as a simple command" and "approved with shell
// metacharacters present" are different facts about the same decision.
@id("shell_trusted_compound_command")
@sentinel_obligation("approve")
@sentinel_reason("Shell command containing metacharacters that permit chaining or redirection.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"shell"
) when {
    principal.trustTier == "trusted" &&
    context.hasShellMetacharacters
};

// Standard tier gets the simple case only, and only inside the workspace.
// Chaining from a standard-tier agent has no permit, so it is denied.
@id("shell_standard_simple_command")
@sentinel_obligation("approve")
@sentinel_reason("Single shell command inside the workspace from a standard-tier agent.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"shell"
) when {
    principal.trustTier == "standard" &&
    !context.hasShellMetacharacters &&
    context.pathsWithinWorkspace &&
    !context.hasParentTraversal
};
