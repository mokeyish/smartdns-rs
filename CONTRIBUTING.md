# Contributing to SmartDNS-rs

Thank you for your interest in contributing to SmartDNS-rs! This document provides guidelines for contributing code to the project.

---

## 🌿 Branch Management Strategy

* The main branch is `main`, used for stable releases.
* **Do not commit code directly to the main branch.**
* Create a new branch from the latest `main` branch for development. Naming conventions:
  * New features: `feat/your-feature-name`
  * Bug fixes: `fix/your-bug-name`
  * Documentation updates: `docs/your-docs-name`

```bash
git checkout main
git pull upstream main
git checkout -b feat/my-new-feature
```

---

## 📝 Commit Message Guidelines

We follow the **Conventional Commits** specification. Commit messages should follow this format:

```text
<type>(<scope>): <subject>

<body>
```

### Commit Type Categories

| Type | Meaning | When to Use |
| :--- | :--- | :--- |
| **feat** | New Feature | Introduces a new feature or functionality |
| **fix** | Bug Fix | Fixes a bug or vulnerability in the code |
| **docs** | Documentation | Only modifies documentation, README, or comments |
| **style** | Code Style | Changes that don't affect code meaning (formatting, whitespace, missing semicolons) |
| **refactor** | Refactoring | Large or medium refactoring of logic structure or core modules |
| **tweak** | Tweaks | Local code adjustments, minor optimizations, or renaming |
| **perf** | Performance | Improves performance, load speed, or reduces memory usage |
| **test** | Tests | Adds, modifies, or removes test code |
| **chore** | Build/Tools | Modifies build tools, dependencies (e.g., npm, Maven configs), or utility tools |
| **ci** | CI Configuration | Modifies continuous integration scripts or config files (e.g., GitHub Actions, GitLab CI) |
| **revert** | Revert | Reverts a previous commit |

*Examples:*
* Refactoring: `refactor(auth): rewrite the token validation module for WeChat login`
* Tweaks: `tweak(auth): optimize variable naming and remove redundant checks in the WeChat login component`

⚠️ **Breaking Changes**: If your changes will break previous code, add `!` after the type or note it in the footer.

---

## 🚀 Creating Merge Requests (MR) / Pull Requests (PR)

When you've finished your code changes and are ready to submit a Pull Request (PR) or Merge Request (MR), follow these steps:

### 1. Squash Intermediate Commits

Use interactive rebase to clean up your local commit history (assuming you've made 3 commits after branching from `main`):

```bash
git rebase -i HEAD~3
```

In the editor that opens, change `pick` to `squash` (or `s`) for the second and subsequent lines, save, and exit. Then, **modify the commit message to match the format specified above**.

### 2. Rebase on Latest Upstream Code

Ensure your changes are based on the latest upstream `main` branch to avoid merge commits:

```bash
git checkout main
git pull upstream main
git checkout your-branch
git rebase main
```

*If you encounter conflicts during rebase, resolve them according to the prompts, then execute `git add .` and `git rebase --continue`.*

### 3. Push to Remote Branch and Create MR/PR

Due to squashing and rebasing, you may need to force-push your remote branch:

```bash
git push origin your-branch --force
```

Create an MR/PR on the original project's page. Clearly explain what you modified. If there's a related issue, include `Closes #IssueNumber` in the description.

---

## Code Quality Standards

Before submitting your PR/MR, ensure:

* All tests pass: `just test`
* Code is formatted: `just fmt`
* No clippy warnings: `just clippy`
* Commit messages follow the Conventional Commits format

---

## Testing Requirements

* Add unit tests for new features
* Place unit tests at the end of the file, after all public code
* Test both success and error paths
* Verify actual content in tests, not just `Some`/`None` existence

---

## Style Guidelines

* Write clear, maintainable code
* Prefer simplicity over cleverness
* Document your code with doc comments
* Follow the existing code style and patterns

---

## Getting Help

* Check the [README](README.md) for project overview
* Review the [AGENTS.md](AGENTS.md) for development guides
* Open an issue for bug reports or feature requests

---

Thank you for your contribution! 🎉
