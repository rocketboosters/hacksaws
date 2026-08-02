# IAM roles and trust

Create an agent role whose default trust principal is the selected caller:

```shell
hacksaws iam role create AgentSession --trust-caller --profile admin --dry-run
hacksaws iam role create AgentSession --trust-caller --profile admin --yes
```

The caller needs both sides of authorization:

- The role trust policy allows that caller principal to use `sts:AssumeRole`.
- An identity policy on the caller allows `sts:AssumeRole` on that role ARN.

Inspect and modify trust explicitly:

```shell
hacksaws iam role trust get AgentSession --profile admin
hacksaws iam role trust edit AgentSession --profile admin
hacksaws iam role trust add user AgentSession alice --profile admin
hacksaws iam role trust remove user AgentSession alice --profile admin
hacksaws iam role trust grant group AgentSession Developers --profile admin
hacksaws iam role trust add group-members Developers alice bob --profile admin
```

IAM groups are not valid trust principals. `trust grant group` manages an
identity policy on the group. `trust add group-members` resolves current group
members and writes individual user principals; later membership changes do not
automatically change that trust policy. Names and ARNs are interchangeable where
AWS permits resolution.

Role commands also support get/list/update/delete, tag CRUD, managed-policy
attach/detach, and inline-policy list/get/export/put/edit/delete. Use
`--dry-run` on every mutation.

Local document leaves accept ergonomic order-independent input:

```shell
hacksaws iam role inline-policy put Agent LocalRead ./read.yaml
hacksaws iam role inline-policy put Agent ./read.yaml LocalRead
hacksaws iam role inline-policy put Agent --policy-name LocalRead --file ./read.yaml
hacksaws iam role trust set Agent ./trust.yaml
hacksaws iam role trust set ./trust.yaml Agent
hacksaws iam role trust set --role Agent --file ./trust.yaml
```

Path syntax, a supported extension, or an existing file identifies the file.
Ambiguous inputs fail before AWS access with the explicit flags to use.

Create/replace never adopts an unowned same-name role. `adopt` is the explicit
ownership transition and reconciles protected ownership tags while preserving
trust, permissions, and unrelated tags; `release` removes only those protected
tags. A legacy safely-owned role can be upgraded by reviewing `adopt --dry-run`.

Every mutation preview shows credential-free identity/ownership, exact scalar
before→after changes, ordered AWS actions, dependencies, warnings, and required
confirmation. Results report the applied actions, ARN/ID, console link, and
recovery journal. Documents and tag values are represented only by
non-reversible summaries. Ordinary mutations require exact `yes`; role deletion
requires the exact role name. `--yes` is the explicit noninteractive form.

The complete role command families are:

```text
hacksaws iam role create|get|list|update|delete ...
hacksaws iam role attach|detach ROLE POLICY ...
hacksaws iam role adopt|release ROLE ...
hacksaws iam role tag list|set|remove ROLE ...
hacksaws iam role inline-policy list|get|export|put|edit|delete ROLE ...
hacksaws iam role trust get|set|edit|export|check ROLE ...
hacksaws iam role trust add|remove user|role|account|principal ROLE PRINCIPAL ...
hacksaws iam role trust add|remove|sync group-members GROUP [MEMBER]... ...
hacksaws iam role trust grant|revoke group ROLE GROUP ...
```

Run `hacksaws iam role COMMAND --help` at the terminal leaf for input, selector,
output, and safety details. `adopt` places an existing role under Hacksaws
ownership; `release` removes that ownership without deleting the role.
