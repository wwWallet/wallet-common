<img src="https://demo.wwwallet.org/wallet_192.png" width="80" style="max-width: 100%; float:left; margin-right: 20px;"/>

# Wallet Common

This library serves as a centralized collection of reusable component-functions that are shared across multiple software stacks. Its main goal is to promote consistency, reduce duplication and streamline development by providing well-tested, commonly used utilities and components in one place.

## Components

### Key Components

- Credential Parsing
- Credential Rendering
- Credential Verification
- Common type definitions
- Common JSON schema definition for response validations

### Interfaces

The `interface.ts` file defines all the interfaces that are exported from this library.

## Development

### Pre-commit Hook

We use [pre-commit](https://pre-commit.com/) to enforce our `.editorconfig` before code is committed.

#### One-time setup

```
# install pre-commit if you don’t already have it
pip install pre-commit       # or brew install pre-commit / pipx install pre-commit

# enable the git hook in this repo
pre-commit install

# optional: clean up the repo on demand
pre-commit run --all-files

git add -A
```

#### Local checks without committing

Run only the EditorConfig check, without running auto-fixers:

```sh
pre-commit run editorconfig-checker --all-files
```

Omit `--all-files` to check only staged files. The first run installs the pinned native checker in pre-commit's cache. This check reports violations without changing or staging files.

#### What happens on commit

- Auto-fixers run (e.g. add final newlines).
- After the auto-fixers, editorconfig-checker validates staged files.
- If violations remain, fix them manually until the commit passes.

### Pull requests

Pull requests are squash-merged: the **PR title** becomes the commit title on `master` and the **PR description** becomes the commit body. Branch's own commit messages are not kept.

The title must follow [Conventional Commits](https://www.conventionalcommits.org/); the `Validate PR title` check enforces this:

```
type(optional-scope): lower-case summary
```

- Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore`.
- Examples: `fix(rendering): fall back to simple card when SVG template 404s`, `chore(deps): bump vitest`.
- Breaking change for consumers (removed or renamed export, changed type, stricter schema, new Node requirement): add `!` after the type, e.g. `feat(schemas)!: require credential_configuration_ids`, and describe the break in the PR description.
- Runtime dependency bump: `fix(deps): …`. Dev-only dependency bump: `chore(deps): …`.
- Undoing an earlier change: title it by its effect on consumers, e.g. `fix: revert …` for a patch or `feat!: …` if the revert removes something consumers use.
- To fix a failing check, edit the title; the check re-runs automatically.

## Releases & versioning

wallet-common follows [semantic versioning](https://semver.org/). Every merge to `master` runs the `release` workflow, which uses [semantic-release](https://github.com/semantic-release/semantic-release) to work out the next version from the commits merged since the last `v*` tag (PR title and description). If there are several, the largest bump wins:

| PR title                                           | Release (e.g. from `1.0.1`) |
| -------------------------------------------------- | ---------------------------- |
| any type with `!`, e.g. `feat!: …`                 | major (`2.0.0`)              |
| `feat: …`                                          | minor (`1.1.0`)              |
| `fix: …`, `perf: …`                                | patch (`1.0.2`)              |
| `docs`, `test`, `ci`, `build`, `refactor`, `chore` | no release                   |

A line starting with `BREAKING CHANGE:` (or `BREAKING-CHANGE:`) in the PR description also makes a major release, whatever the title.

When there is something to release, the workflow writes the version into `package.json`, commits it to `master` as `chore(release): X.Y.Z [skip ci]`, tags that commit `vX.Y.Z` and publishes a GitHub Release with the notes.

- The version in `package.json` is owned by the release workflow. Don't change it by hand.
- Consumers pin an exact tag: `"wallet-common": "git+https://github.com/wwWallet/wallet-common.git#vX.Y.Z"`.
