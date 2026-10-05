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

### Yarn Classic Git installs

Git consumers run this library's `prepare` script, including an installation of
its development dependencies even during a production install. `.yarnrc` puts
that installation's cache in `.yarn-cache` relative to the library checkout and
limits network concurrency to one. This separates preparation from the consumer's
cache to avoid overlapping extraction into the same directories. The cache is
ignored by Git and excluded from the package's `files` list.

Avoid setting `YARN_CACHE_FOLDER` to a shared cache when installing Git consumers:
the environment override also applies to preparation and defeats this isolation.

Run `node scripts/test-git-install.cjs` to verify a production Git install prepares
and packs a fixture using the repository configuration. This test runs offline
and needs Node.js, Yarn v1 and Git.

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
