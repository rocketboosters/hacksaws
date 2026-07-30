# Hacksaws

[![Checks](https://github.com/rocketboosters/hacksaws/actions/workflows/checks.yaml/badge.svg)](https://github.com/rocketboosters/hacksaws/actions/workflows/checks.yaml)
[![PyPI version](https://img.shields.io/pypi/v/hacksaws.svg)](https://pypi.org/project/hacksaws/)
[![Python versions](https://img.shields.io/pypi/pyversions/hacksaws.svg)](https://pypi.org/project/hacksaws/)
[![License](https://img.shields.io/pypi/l/hacksaws.svg)](https://github.com/rocketboosters/hacksaws/blob/main/LICENSE)

Hacksaws is a command-line utility for AWS profiles that use dynamic
authentication methods such as multi-factor authentication (MFA). It replaces a
profile's long-term access key and secret with temporary session credentials,
while storing the long-term credentials in a local backup until the next login
or logout.

Only MFA-based dynamic login is currently supported. Hacksaws supports Python
3.13 and 3.14.

## Installation

Install Hacksaws as an isolated command-line tool with
[uv](https://docs.astral.sh/uv/):

```shell
uv tool install hacksaws
```

As a fallback, install it into the active Python environment with pip:

```shell
python -m pip install hacksaws
```

## Usage

Log in with MFA by supplying an AWS profile and the current MFA code:

```shell
hacksaws mfa login <PROFILE_NAME> <MFA_CODE>
```

The `--lifespan` option changes how long the temporary session remains valid.
The default is 12 hours (`--lifespan=43200` seconds). AWS allows at most 24
hours, and the profile's role or account policy may set a lower maximum.

Hacksaws can also log a container engine into Amazon ECR in the profile's
default region. Docker is used by default:

```shell
hacksaws mfa login <PROFILE_NAME> <MFA_CODE> --ecr
```

Select Podman by adding `--podman`. The option chooses the container engine but
does not enable ECR by itself, so use it together with `--ecr`:

```shell
hacksaws mfa login <PROFILE_NAME> <MFA_CODE> --ecr --podman
```

Use `--ecr-region` more than once to add regions. The profile's primary region
is processed first, followed by each additional region once in the order
provided:

```shell
hacksaws mfa login <PROFILE_NAME> <MFA_CODE> \
  --ecr \
  --ecr-region=eu-central-1 \
  --ecr-region=us-west-2 \
  --ecr-region=ca-central-1
```

Log out of the AWS profile and restore its long-term credentials:

```shell
hacksaws mfa logout <PROFILE_NAME>
```

Add `--ecr` to the logout command to log Docker out of the configured ECR
registries as well:

```shell
hacksaws mfa logout <PROFILE_NAME> --ecr
```

Use the same `--podman` selection when logging Podman out:

```shell
hacksaws mfa logout <PROFILE_NAME> --ecr --podman
```

Use `--directory` to select a different AWS configuration directory:

```shell
hacksaws mfa login <PROFILE_NAME> <MFA_CODE> --directory=/path/to/aws
```

For directories in the `~/.aws-<NAME>` form, `--name` is shorthand for choosing
the named account directory:

```shell
hacksaws mfa login <PROFILE_NAME> <MFA_CODE> --name=sandbox
```

The action aliases `in` and `out`, the directory alias `--dir`, and the account
name alias `--account-name` remain available.

## Requiring MFA

The repository includes
[an example IAM policy](https://github.com/rocketboosters/hacksaws/blob/main/example_mfa_iam_policy.json)
that lets users manage their own credentials while requiring MFA for other AWS
operations.

AWS provides further guidance:

- [Allow MFA-authenticated IAM users to manage their own credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_my-sec-creds-self-manage-mfa-only.html)
- [Allow IAM users to self-manage an MFA device](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_iam_mfa-selfmanage.html)
- [Configure MFA-protected API access](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html)
- [Set an IAM account password policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html)

## Development

Install the locked Python and Node.js development dependencies:

```shell
uv sync --locked --all-groups
npm ci
```

Format the repository:

```shell
uv run task format
```

Run the same non-mutating quality and test checks used by GitHub Actions:

```shell
uv run task check
```

Run an individual check when iterating:

```shell
uv run task lint
uv run task test
uv run task build
```

## Release process

Publishing is handled by the
[`publish.yaml`](https://github.com/rocketboosters/hacksaws/blob/main/.github/workflows/publish.yaml)
GitHub Actions workflow and PyPI trusted publishing. Each successful release
publishes the wheel and source distribution to PyPI, then creates a GitHub
Release for the same tag with those exact artifacts attached.

1. Update `project.version` in `pyproject.toml`.
2. Run `uv lock`, `npm ci`, and `uv run task check`.
3. Build locally with `uv build` and inspect the wheel and source distribution.
4. Merge the version change to `main`.
5. Create and push a `v<version>` tag, such as `v0.3.2`.

The workflow verifies that the tag exactly matches the project version before it
builds once, publishes the resulting artifacts to PyPI, and creates the GitHub
Release only after PyPI succeeds. The repository's `pypi` environment must be
configured as a trusted publisher for owner `rocketboosters`, repository
`hacksaws`, workflow `publish.yaml`, and environment `pypi`.
