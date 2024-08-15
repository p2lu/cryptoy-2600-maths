from math import (
    gcd,
)

from cryptoy.utils import (
    draw_random_prime,
    int_to_str,
    modular_inverse,
    pow_mod,
    str_to_int,
)


def keygen() -> dict:
    e = 0x10001
    p = draw_random_prime()
    q = draw_random_prime()
    phi = (p - 1) * (q - 1)
    d = modular_inverse(e, phi)
    return {"public_key": (e, p * q), "private_key": d}



def encrypt(msg: str, public_key: tuple) -> int:
    integer_message = str_to_int(msg)
    if integer_message < public_key[1]:
        return pow_mod(integer_message, public_key[0], public_key[1])
    else:
        RuntimeError("Failed")



def decrypt(msg: int, key: dict) -> str:
    integer_message = pow_mod(msg, key["private_key"], key["public_key"][1])
    return int_to_str(integer_message)