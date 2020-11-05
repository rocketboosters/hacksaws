import configparser
import os

import boto3

from hacksaws import _configs


def logout(context: _configs.Context):
    """Cleans up a login session for the aws user."""
    if not context.storage_path.exists():
        return

    credentials = configparser.ConfigParser()
    credentials.read(context.credentials_path)

    storage = configparser.ConfigParser()
    storage.read(context.storage_path)

    # Copy stored values.
    credentials[context.profile] = storage[context.profile]

    with open(context.credentials_path, "w+") as fp:
        credentials.write(fp)

    os.remove(context.storage_path)


def login(context: _configs.Context):
    """Executes a login process."""
    configs = configparser.ConfigParser()
    configs.read(context.config_path)
    profile_configs = configs[f"profile {context.profile}"]

    session = boto3.Session(profile_name=context.profile)
    client = session.client("sts")
    response = client.get_session_token(
        DurationSeconds=context.args.lifespan,
        SerialNumber=profile_configs["mfa_serial"],
        TokenCode=context.args.mfa_code,
    )
    creds = response["Credentials"]

    credentials = configparser.ConfigParser()
    credentials.read(context.credentials_path)

    storage = configparser.ConfigParser()
    storage[context.profile] = credentials[context.profile]

    with open(context.storage_path, "w+") as fp:
        storage.write(fp)

    credentials[context.profile] = {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }

    with open(context.credentials_path, "w+") as fp:
        credentials.write(fp)
