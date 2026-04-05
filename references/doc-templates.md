# Documentation System Templates

## CLAUDE.md Index Specification

CLAUDE.md is the project's navigation entry point, not a place for detailed content. Specification:
- Total lines ≤ 100
- Only contains: one-line description + directory navigation + command quick-reference + skill quick-reference
- All detailed content stored in docs/ sub-documents
- Use relative path links to sub-documents

## docs/ Sub-document Specification

### General Rules
- Each sub-document ≤ 150 lines, split if exceeding
- Every directory must have INDEX.md as navigation
- INDEX.md only contains sub-document links and one-line descriptions
- Documents use Markdown, code blocks annotated with language

### INDEX.md Template

```markdown
# [Directory Name]

[One-line description of what this directory covers]

## Contents

| Document | Description |
|----------|-------------|
| [doc-name](./doc-name.md) | One-line description |
```

### architecture/ Document Structure

**system-overview.md** should contain:
- System positioning (one line)
- Core modules and responsibilities (table)
- Inter-module relationships (text description or simple ASCII diagram)
- Data flow
- Key design decisions

**tech-stack.md** should contain:
- Language and version
- Framework and version
- Key dependencies and purposes (table)
- Infrastructure (DB / Cache / MQ / Storage)
- Deployment environment

**db-schema.md** (if database exists) should contain:
- Core tables and purposes
- Table relationships
- Key indexes
- Common query patterns

**api-reference.md** (if API exists) should contain:
- API grouping
- Core endpoints (path / method / purpose)
- Authentication method
- Error code conventions

### implementation/ Document Structure

Split by functional modules, one document per module, containing:
- Module responsibilities
- Core classes/functions
- Key workflows (step list)
- Configuration items
- Notes and caveats

### conventions/ Document Structure

**must-follow.md**:
- Coding style (corresponding linter config)
- Naming conventions
- Git commit format
- PR/MR workflow
- Testing requirements

**must-not.md**:
- Prohibited code patterns (with examples)
- Prohibited dependency usage patterns
- Prohibited deployment operations

**secure-coding.md**:
- Injected from harness/references/secure-coding.md
- Tailored by project tech stack

### pitfalls/ Document Structure

Categorized by tech stack or scenario, each entry containing:
- Problem description
- Root cause analysis
- Solution
- Prevention measures

### backlog/ Document Structure

**optimization.md**:
- Performance bottlenecks and optimization directions
- Architecture improvement suggestions
- Tech debt cleanup

**features.md**:
- Features to implement list
- Priority annotations
- Dependencies
