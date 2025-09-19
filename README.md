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

#### What happens on commit

- Auto-fixers run (e.g. add final newlines).
- After the auto-fixers, the editorconfig-checker runs inside Docker to validate all staged files.
- If violations remain, fix them manually until the commit passes.
