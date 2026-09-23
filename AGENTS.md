# AGENTS.md instructions for /Users/kasunranasinghe/Projects/Rust/simple-ldap

## Skills
A skill is a set of local instructions to follow that is stored in a `SKILL.md` file. Below is the list of skills that can be used. Each entry includes a name, description, and file path so you can open the source for full instructions when using a specific skill.

### Available skills
- rust-best-practices: Covers idiomatic Rust practices, including composition, error handling, and ownership. (file: /Users/kasunranasinghe/.codex/skills/rust/rust-best-practices/SKILL.md)
- rust-documentation-best-practices: How to write excellent documentation for Rust code using rustdoc. (file: /Users/kasunranasinghe/.codex/skills/rust/rust-documentation-best-practices/SKILL.md)
- rust-dry-principle: How to avoid code duplication in Rust using functions, macros, and traits. (file: /Users/kasunranasinghe/.codex/skills/rust/rust-dry-principle/SKILL.md)
- rust-idioms-unofficial: Apply Rust idioms from the Rust Unofficial Patterns (Idioms chapter) when writing, reviewing, refactoring, or explaining Rust code. Use for questions like “make this more idiomatic,” “which idiom applies here,” or “show examples of Rust idioms.” (file: /Users/kasunranasinghe/.codex/skills/rust/rust-idioms-unofficial/SKILL.md)
- rust-kiss-principle: Focuses on writing simple, clear, and readable Rust code. (file: /Users/kasunranasinghe/.codex/skills/rust/rust-kiss-principle/SKILL.md)
- rust-performance-best-practices: Tips for writing high-performance Rust code, leveraging zero-cost abstractions. (file: /Users/kasunranasinghe/.codex/skills/rust/rust-performance-best-practices/SKILL.md)
- rust-solid-principles: Applies SOLID principles to Rust, using traits and composition to write maintainable code. (file: /Users/kasunranasinghe/.codex/skills/rust/rust-solid-principles/SKILL.md)
- skill-creator: Guide for creating effective skills. This skill should be used when users want to create a new skill (or update an existing skill) that extends Codex's capabilities with specialized knowledge, workflows, or tool integrations. (file: /Users/kasunranasinghe/.codex/skills/.system/skill-creator/SKILL.md)
- skill-installer: Install Codex skills into $CODEX_HOME/skills from a curated list or a GitHub repo path. Use when a user asks to list installable skills, install a curated skill, or install a skill from another repo (including private repos). (file: /Users/kasunranasinghe/.codex/skills/.system/skill-installer/SKILL.md)

### How to use skills
- Discovery: The list above is the skills available in this session (name + description + file path). Skill bodies live on disk at the listed paths.
- Trigger rules: If the user names a skill (with `$SkillName` or plain text) OR the task clearly matches a skill's description shown above, you must use that skill for that turn. Multiple mentions mean use them all.
- Missing/blocked: If a named skill isn't in the list or the path can't be read, say so briefly and continue with the best fallback.
- How to use a skill (progressive disclosure):
  1. After deciding to use a skill, open its `SKILL.md`. Read only enough to follow the workflow.
  2. When `SKILL.md` references relative paths (e.g., `scripts/foo.py`), resolve them relative to the skill directory listed above first, and only consider other paths if needed.
  3. If `SKILL.md` points to extra folders such as `references/`, load only the specific files needed for the request; don't bulk-load everything.
  4. If `scripts/` exist, prefer running or patching them instead of retyping large code blocks.
  5. If `assets/` or templates exist, reuse them instead of recreating from scratch.
- Coordination and sequencing:
  - If multiple skills apply, choose the minimal set that covers the request and state the order you'll use them.
  - Announce which skill(s) you're using and why (one short line). If you skip an obvious skill, say why.
- Context hygiene:
  - Keep context small: summarize long sections instead of pasting them; only load extra files when needed.
  - Avoid deep reference-chasing: prefer opening only files directly linked from `SKILL.md` unless you're blocked.
  - When variants exist (frameworks, providers, domains), pick only the relevant reference file(s) and note that choice.
- Safety and fallback: If a skill can't be applied cleanly (missing files, unclear instructions), state the issue, pick the next-best approach, and continue.


## graphify

This project has a graphify knowledge graph at graphify-out/.

Rules:
- Before answering architecture or codebase questions, read graphify-out/GRAPH_REPORT.md for god nodes and community structure
- If graphify-out/wiki/index.md exists, navigate it instead of reading raw files
- For cross-module "how does X relate to Y" questions, prefer `graphify query "<question>"`, `graphify path "<A>" "<B>"`, or `graphify explain "<concept>"` over grep — these traverse the graph's EXTRACTED + INFERRED edges instead of scanning files
- After modifying code files in this session, run `graphify update .` to keep the graph current (AST-only, no API cost)
