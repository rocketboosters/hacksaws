import base64
import datetime
import subprocess

import boto3

from hacksaws import _configs


def _do_login(context: _configs.Context, registry: str):
    """Carry out the loging process for a region-specific registry."""
    print(f"[STARTED]: Logging into {registry}", flush=True)
    parts = registry.split(".")
    account_id = parts[0]
    region_name = parts[3]

    session = boto3.Session(profile_name=context.profile, region_name=region_name)
    response = (
        session.client("ecr")
        .get_authorization_token(registryIds=[account_id])
        .get("authorizationData", {})[0]
    )

    user, password = (
        base64.b64decode(response["authorizationToken"].encode()).decode().split(":")
    )

    cmd = [
        "docker",
        "login",
        f"--username={user}",
        "--password-stdin",
        registry,
    ]
    subprocess.run(cmd, input=password.encode(), check=True)

    expires_at: datetime.datetime = (
        response["expiresAt"].astimezone(datetime.timezone.utc).replace(tzinfo=None)
    )

    delta: datetime.timedelta = expires_at - datetime.datetime.utcnow()
    hours = int(round(delta.total_seconds() / 3600))
    print(f"[SUCCESS]: Login session will expire in {hours} hours", flush=True)


def login(context: _configs.Context, aws_account: _configs.AwsAccount):
    """Logs into the AWS ECR registry in the given account."""
    for registry in aws_account.ecr_registries:
        _do_login(context, registry)


def logout(aws_account: _configs.AwsAccount):
    """Logs out of the registry for the given AWS account."""
    for registry in aws_account.ecr_registries:
        cmd = ["docker", "logout", registry]
        subprocess.run(cmd, check=True)
