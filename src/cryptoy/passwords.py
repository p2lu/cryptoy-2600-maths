import hashlib
import os
from random import (
    Random,
)

import names


def hash_password(password: str) -> str:
    return hashlib.sha3_256(password.encode()).hexdigest()


def random_salt() -> str:
    return bytes.hex(os.urandom(32))


def generate_users_and_password_hashes(
    passwords: list[str], count: int = 32
) -> dict[str, str]:
    rng = Random()  # noqa: S311

    users_and_password_hashes = {
        names.get_full_name(): hash_password(rng.choice(passwords))
        for _i in range(count)
    }
    return users_and_password_hashes


def attack(passwords: list[str], passwords_database: dict[str, str]) -> dict[str, str]:
    users_and_passwords = {}

    hash = {}
    for password in passwords:
        hash = hash_password(password)
        hash[password] = hash
    for _, (user, hash1) in enumerate(passwords_database.items()):
        for __, (password, hash2) in enumerate(hash.items()):
            if hash1 == hash2:
                users_and_passwords[user] = password
    return users_and_passwords


def fix(
    passwords: list[str], passwords_database: dict[str, str]
) -> dict[str, dict[str, str]]:
    hashlist_passwd = attack(passwords, passwords_database)
    users_and_salt = {}
    new_database = {}
    
    for (user, passwd) in hashlist_passwd.items():
        salt = random_salt()
        users_and_salt = {
            "password_hash": hash_password(passwd + salt),
            "password_salt": salt,
        }
        new_database[user] = users_and_salt

    return new_database



def authenticate(
    user: str, password: str, new_database: dict[str, dict[str, str]]
) -> bool:
    arr = new_database[user]
    hash = hash_password(password + arr["password_salt"])
    return arr["password_hash"] == hash
