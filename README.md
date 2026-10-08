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

#### What happens on commit

- Auto-fixers run (e.g. add final newlines).
- After the auto-fixers, the editorconfig-checker runs inside Docker to validate all staged files.
- If violations remain, fix them manually until the commit passes.

### Pull requests

Pull requests are squash-merged, and the **PR title** becomes the commit message on `master`. Your branch's own commit messages are not kept, so commit however you like.

The title must follow [Conventional Commits](https://www.conventionalcommits.org/); the `Validate PR title` check enforces this:

```
type(optional-scope): lower-case summary
```

- Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore`, `revert`.
- Examples: `fix(rendering): fall back to simple card when SVG template 404s`, `chore(deps): bump vitest`.
- Breaking change for consumers (removed or renamed export, changed type, stricter schema, new Node requirement): add `!` after the type, e.g. `feat(schemas)!: require credential_configuration_ids`, and describe the break in the PR description.
- Runtime dependency bump: `fix(deps): …`. Dev-only dependency bump: `chore(deps): …`.
- To fix a failing check, edit the title; the check re-runs automatically.

## Releases & versioning

wallet-common follows [semantic versioning](https://semver.org/). Every merge to `master` runs the `release` workflow, which uses [semantic-release](https://github.com/semantic-release/semantic-release) to work out the next version from the PR titles merged since the last `v*` tag:

| PR title | Release |
|---|---|
| `feat: …` | minor (`1.1.0`) |
| `fix: …`, `perf: …`, `revert: …` | patch (`1.0.1`) |
| any type with `!`, e.g. `feat!: …` | major (`2.0.0`) |
| `docs`, `test`, `ci`, `build`, `refactor`, `chore` | no release |

When there is something to release, the workflow writes the version into `package.json`, commits it to `master` as `chore(release): X.Y.Z`, tags that commit `vX.Y.Z` and publishes a GitHub Release with the notes.

- The version in `package.json` is owned by the release workflow. Don't change it by hand.
- Consumers pin an exact tag: `"wallet-common": "git+https://github.com/wwWallet/wallet-common.git#vX.Y.Z"`.
