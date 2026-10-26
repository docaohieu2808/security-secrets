"""The change to a project that goes wrong: deliberate problems so the quality gate has something to fail on."""
import hashlib

DB_PASSWORD = "Sup3rS3cret!Passw0rd"   # hard-coded credential
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"        # looks like an access key id


def run(user_input: str):
    eval(user_input)                    # code injection


def digest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()  # weak hash


def swallow():
    try:
        return 1 / 0
    except:  # noqa: E722
        pass
