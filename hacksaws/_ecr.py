import base64
import datetime
import subprocess

import boto3

from hacksaws import _configs


def login(context: _configs.Context, aws_account: _configs.AwsAccount):
    """Logs into the AWS ECR registry in the given account."""
    session = boto3.Session(profile_name=context.profile)
    response = (
        session.client("ecr")
        .get_authorization_token(registryIds=[aws_account.id])
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
        aws_account.ecr_registry,
    ]
    subprocess.run(cmd, input=password.encode(), check=True)

    expires_at: datetime.datetime = (
        response["expiresAt"].astimezone(datetime.timezone.utc).replace(tzinfo=None)
    )

    delta: datetime.timedelta = expires_at - datetime.datetime.utcnow()
    print(
        "[SUCCESS]: Login session will expire in {} hours".format(
            int(round(delta.total_seconds() / 3600))
        )
    )


def logout(aws_account: _configs.AwsAccount):
    """Logs out of the registry for the given AWS account."""
    cmd = ["docker", "logout", aws_account.ecr_registry]
    subprocess.run(cmd, check=True)
