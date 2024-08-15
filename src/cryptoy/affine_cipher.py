from math import (
    gcd,
)

from cryptoy.utils import (
    str_to_unicodes,
    unicodes_to_str,
)

# TP: Chiffrement affine


def compute_permutation(a: int, b: int, n: int) -> list[int]:
    return [((a * i + b) % n) for i in range(n)]


def compute_inverse_permutation(a: int, b: int, n: int) -> list[int]:
    perm = compute_permutation(a, b, n)
    results = [i for val, i in sorted(enumerate(perm), key=lambda x: x[1])]
    return results




def encrypt(msg: str, a: int, b: int) -> str:
    perm = compute_permutation(a, b, 0x110000)
    uni = str_to_unicodes(msg)
    uni = [perm[uni[i]] for i in range(len(uni))]
    return unicodes_to_str(uni)



def encrypt_optimized(msg: str, a: int, b: int) -> str:
    uni_msg = str_to_unicodes(msg)
    cipher = [(a * unicode + b) % 0x110000 for unicode in uni_msg]
    return unicodes_to_str(cipher)



def decrypt(msg: str, a: int, b: int) -> str:
    uni = str_to_unicodes(msg)
    perm = compute_inverse_permutation(a, b, 0x110000)
    uni = [perm[uni[i]] for i in range(len(uni))]
    return unicodes_to_str(uni)




def decrypt_optimized(msg: str, a_inverse: int, b: int) -> str:
    uni = str_to_unicodes(msg)
    plain = [a_inverse * (unicode - b) % 0x110000 for unicode in uni]
    return unicodes_to_str(plain)



def compute_affine_keys(n: int) -> list[int]:
    return [i for i in range(n) if gcd(i, n) == 1]


def compute_affine_key_inverse(a: int, affine_keys: list, n: int) -> int:
    for key in affine_keys:
        if (a * key % n) == 1:
            return key

    # Si a_1 n'existe pas, alors a n'a pas d'inverse, on lance une erreur:
    raise RuntimeError(f"{a} has no inverse")


def attack() -> tuple[str, tuple[int, int]]:
    s = "࠾ੵΚઐ௯ஹઐૡΚૡೢఊஞ௯\u0c5bૡీੵΚ៚Κஞїᣍફ௯ஞૡΚր\u05ecՊՊΚஞૡΚՊեԯՊ؇ԯրՊրր"
    # trouver msg, a et b tel que affine_cipher_encrypt(msg, a, b) == s
    # avec comme info: "bombe" in msg et b == 58

    b = 58
    a_val = compute_affine_keys(0x110000)
    for a in a_val:
        plaintext = decrypt(s, a, b)
        if "bombe" in plaintext:
            return (plaintext, (a, b))
    
    # raise RuntimeError("Failed to attack")


def attack_optimized() -> tuple[str, tuple[int, int]]:
    s = (
        "જഏ൮ൈ\u0c51ܲ೩\u0c51൛൛అ౷\u0c51ܲഢൈᘝఫᘝా\u0c51\u0cfc൮ܲఅܲᘝ൮ᘝܲాᘝఫಊಝ"
        "\u0c64\u0c64ൈᘝࠖܲೖఅܲఘഏ೩ఘ\u0c51ܲ\u0c51൛൮ܲఅ\u0cfc\u0cfcඁೖᘝ\u0c51"
    )
    # trouver msg, a et b tel que affine_cipher_encrypt(msg, a, b) == s
    # avec comme info: "bombe" in msg

    possibles = compute_affine_keys(0x110000)
    for a in range(1, len(possibles)):
        try:
            a_inverse = compute_affine_key_inverse(a, possibles, 0x110000)
        except:
            continue
        for b in range(1, 15000):
            message = decrypt_optimized(s, a_inverse, b)
            if "bombe" in message:
                return (message, (a, b))
    
    # raise RuntimeError("Failed to attack")
