# Login pathways

## Browser login (`web` / `pk`)

Browser login uses the AWS CLI login credential provider and does not require an
existing profile. Hacksaws creates both the config and credentials destinations
when needed. The package includes the Botocore CRT dependency required to verify
these credentials.

```shell
hacksaws web in debug
hacksaws pk in default --name default
```

`web` and `pk` are equivalent. `in` aliases `login`; `out` aliases `logout`.

## MFA login

MFA requires persistent source credentials. `PROFILE --name LOCATION` selects
the source profile and `~/.aws-LOCATION` directory.

```shell
hacksaws mfa in admin --name horizon 123456
hacksaws mfa in admin --name horizon --to default:debug 123456
```

The source credentials should have only bootstrap permissions. See
[Security model](security-model.md).

## Roles and session policies

`--role ARN_OR_NAME` assumes a role after authentication. `--policy` optionally
intersects that role with a session policy:

```shell
hacksaws web in debug --role AgentSession --policy ./agent.yaml
```

`--boundary NAME` / `--as NAME` loads a saved role, policy, external ID, and
duration. `+NAME` or `--target NAME` loads a complete saved login preset. `+` is
the documented shorthand prefix, but any leading non-alphanumeric character is
accepted so users can choose one their shell handles conveniently; the remaining
characters are the target name.

ECR login deliberately uses the intermediate authenticated credentials before
the final boundary credentials replace them.

## Destination aliases

`.` and `default` mean `~/.aws` when used as locations and the `default` profile
when used as profiles. `--to .:.` and `--to default:default` are equivalent.
