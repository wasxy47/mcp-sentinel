// 30-database.cedar — SQL-shaped arguments.
//
// `sqlKind` is produced by static inspection of the statement, not by a model.
// The important design point is how "unknown" is treated: a statement the parser
// could not classify is NOT benign. Unparseable SQL is either exotic-but-fine or
// an injection attempt, and only one of those two possibilities is cheap to be
// wrong about. So it escalates.

@id("db_select_single_statement")
@sentinel_obligation("allow")
@sentinel_reason("Single-statement read-only query.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"database"
) when {
    context.sqlKind == "select" &&
    !context.sqlIsMultiStatement &&
    !context.sqlIsDestructive
};

// Multiple statements in one call is the classic injection shape: the intended
// query, a separator, and a payload. Legitimate batch work exists, so this is
// scored rather than forbidden — but it is never silently allowed.
@id("db_multi_statement")
@sentinel_obligation("approve")
@sentinel_reason("The statement contains multiple SQL statements, a common injection shape.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"database"
) when {
    context.sqlIsMultiStatement
};

@id("db_unparseable_statement")
@sentinel_obligation("review")
@sentinel_reason("The statement could not be classified; unparseable SQL is scored, not trusted.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"database"
) when {
    context.sqlKind == "unknown"
};

@id("db_write")
@sentinel_obligation("approve")
@sentinel_reason("Data-modifying statement requires human approval.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"database"
) when {
    ["insert", "update", "delete"].contains(context.sqlKind) &&
    !context.sqlIsDestructive
};

// DDL and anything the extractor marked destructive (DROP, TRUNCATE, an UPDATE
// or DELETE with no WHERE clause). Trusted tier only, and still a human.
@id("db_destructive_trusted_only")
@sentinel_obligation("approve")
@sentinel_reason("Destructive or schema-altering statement, restricted to trusted agents with human approval.")
permit (
    principal,
    action == Sentinel::Action::"callTool",
    resource in Sentinel::ToolGroup::"database"
) when {
    (context.sqlKind == "ddl" || context.sqlIsDestructive) &&
    principal.trustTier == "trusted"
};
