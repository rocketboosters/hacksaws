# hacksaws

[![PyPI version](https://badge.fury.io/py/hacksaws.svg)](https://badge.fury.io/py/hacksaws)
[![build status](https://gitlab.com/rocket-boosters/hacksaws/badges/main/pipeline.svg)](https://gitlab.com/rocket-boosters/hacksaws/commits/main)
[![coverage report](https://gitlab.com/rocket-boosters/hacksaws/badges/main/coverage.svg)](https://gitlab.com/rocket-boosters/hacksaws/commits/main)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Code style: flake8](https://img.shields.io/badge/code%20style-flake8-white)](https://gitlab.com/pycqa/flake8)
[![Code style: mypy](https://img.shields.io/badge/code%20style-mypy-white)](http://mypy-lang.org/)
[![PyPI - License](https://img.shields.io/pypi/l/hacksaws)](https://pypi.org/project/hacksaws/)

A command line utility for AWS profiles using dynamic authentication 
methods such as MFA. The CLI allows for dynamic logins to update
the credentials for an AWS profile temporarily, while storing the
long-term access key and secret in a backup file until the next
login or logout call is made. That way dynamic logins can be used while
still maintaining the same functional credential interface as
non-dynamic credentials.

At this time only MFA-based dynamic logins are supported, but SSO
and others will be added in the future.

## Usage

To login with MFA, execute the command:

```shell script
$ hacksaws mfa login <PROFILE_NAME> <MFA_CODE>
```

There is a `--lifespan` flag that can be appended here to adjust
the amount of time the profile login is valid for before it expires.
The default is 12 hours (`--lifetime=43200` seconds), but that can
be adjusted to a maximum of 24 hours if the profile login allows
authentication lifespans of that length.

ECR logins with docker can also be handled with the command by adding the `--ecr`
flag. This will the local docker environment into ECR in the default AWS region for
the specified profile.

```shell script
$ hacksaws mfa login <PROFILE_NAME> <MFA_CODE> --ecr
```

It is also possible to login to ECR in multiple regions with the `--ecr-region` flag.

```shell script
$ hacksaws mfa login <PROFILE_NAME> <MFA_CODE> \
    --ecr \
    --ecr-region=eu-central-1 \
    --ecr-region=us-west-2 \
    --ecr-region=ca-central-1
```

ECR will always log into the AWS default region. The `--ecr-region` flag allows for
adding additional regions to the login command.

Then to log out:

```shell script
$ hacksaws mfa logout <PROFILE_NAME>
```

It is possible to log in and out of ECR for the account with that
profile as well by including the `--ecr` flag in the login call.

Alternate directories for the AWS credentials directory can be
specified with the `--directory` flag. 

And for separated AWS credentials directories in the home directory
that follow the pattern `~/.aws-<NAME>`, a `--name` flag can be
specified to use that directory instead of the default `~/.aws`
directory. This is a useful pattern for separating profiles by
account in cases where one has multiple account credentials.

## Requiring MFA

Here's an example policy that allows a user to manage their own
user account settings while requiring MFA.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ViewAccountInfo",
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListAccount*",
        "iam:ListMFADevices",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ViewAndManageTheirUser",
      "Effect": "Allow",
      "Action": [
        "iam:*LoginProfile",
        "iam:*AccessKey*",
        "iam:*SSHPublicKey*",
        "iam:*SigningCertificate*",
        "iam:*ServiceSpecificCredential*",
        "iam:GetUser",
        "iam:ChangePassword"
      ],
      "Resource": "arn:aws:iam::*:user/${aws:username}"
    },
    {
      "Sid": "ManageTheirOwnMFA",
      "Effect": "Allow",
      "Action": [
        "iam:CreateVirtualMFADevice",
        "iam:DeactivateMFADevice",
        "iam:DeleteVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice"
      ],
      "Resource": [
        "arn:aws:iam::*:mfa/${aws:username}",
        "arn:aws:iam::*:user/${aws:username}"
      ]
    },
    {
      "Sid": "DenyAllExceptListedIfNoMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ChangePassword",
        "iam:GetUser",
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

Controlling password quality and expiration policies is an account-level requirement
and more details can be found at
(Setting an account password policy for IAM users)[https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html]

Additional Resources:

- [Allows MFA-authenticated IAM users...](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_my-sec-creds-self-manage-mfa-only.html)
- [IAM: Allows IAM users to self-manage an MFA device](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_iam_mfa-selfmanage.html)
- [Configuring MFA-protected API access](https://docs.amazonaws.cn/en_us/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html)
