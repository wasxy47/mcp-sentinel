// 10-catalog.cedar — discovery and listing.
//
// Cheap, non-mutating, and still worth governing: a catalog listing tells an
// agent what capabilities exist, and hiding a server from a low-trust agent is a
// real control. `discover` is also the agent's first request, so denying it is
// how a fully-revoked agent finds out immediately rather than on its first
// meaningful call.

@id("catalog_discover")
@sentinel_obligation("allow")
@sentinel_reason("Protocol discovery is permitted for all configured agents.")
permit (
    principal,
    action == Sentinel::Action::"discover",
    resource == Sentinel::Endpoint::"gateway"
);

@id("catalog_list")
@sentinel_obligation("allow")
@sentinel_reason("Catalog listing is permitted for all configured agents.")
permit (
    principal,
    action in [
        Sentinel::Action::"listTools",
        Sentinel::Action::"listResources",
        Sentinel::Action::"listPrompts"
    ],
    resource == Sentinel::Endpoint::"gateway"
);

// Prompts are template text that lands directly in the model's context, which
// makes an untrusted server's prompt an injection vector with no argument to
// inspect. Trusted servers only.
@id("catalog_get_prompt_trusted")
@sentinel_obligation("allow")
@sentinel_reason("Prompts from trusted servers are permitted.")
permit (
    principal,
    action == Sentinel::Action::"getPrompt",
    resource
) when {
    resource.server.trust == "trusted" && resource.scanVerdict == "clean"
};

@id("catalog_get_prompt_untrusted")
@sentinel_obligation("review")
@sentinel_reason("Prompt text from an untrusted server is scored before it reaches the model.")
permit (
    principal,
    action == Sentinel::Action::"getPrompt",
    resource
) when {
    resource.server.trust == "untrusted"
};
