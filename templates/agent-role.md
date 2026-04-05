# Agent Role Definition Template

Used for role definitions in `.harness/agents/`.

---

```markdown
# {{ROLE_NAME}} ({{CODE}})

## Responsibilities

- {{responsibility_1}}
- {{responsibility_2}}
- {{responsibility_3}}

## Behavioral Constraints

- MUST: {{required_action}}
- MUST: {{required_action}}
- MUST NOT: {{prohibited_action}}
- MUST NOT: {{prohibited_action}}

## Available Tools

{{all / read-only / custom list}}

## Collaboration Protocol

- With {{role}}: {{interaction_method}}
- With {{role}}: {{interaction_method}}

## Reference Documentation

- {{related_doc_links}}
```
