from cryptoy.utils import (
    str_to_unicodes,
    unicodes_to_str,
)

# TP: Chiffrement de César


def encrypt(msg: str, shift: int) -> str:
    uni = str_to_unicodes(msg)
    ciphertext = [((x + shift) % 0x110000) for x in uni]
    return unicodes_to_str(ciphertext)




def decrypt(msg: str, shift: int) -> str:
    n = -abs(shift)
    return encrypt(msg, n)



def attack() -> tuple[str, int]:
    s = "恱恪恸急恪恳恳恪恲恮恸急恦恹恹恦恶恺恪恷恴恳恸急恵恦恷急恱恪急恳恴恷恩怱急恲恮恳恪恿急恱恦急恿恴恳恪"
    # Il faut déchiffrer le message s en utilisant l'information:
    # 'ennemis' apparait dans le message non chiffré

    for i in range(0x110000):
        plaintext = decrypt(s, i)
        if "ennemis" in plaintext:
            return (plaintext, i)

    # Si on ne trouve pas on lance une exception:
    # raise RuntimeError("Failed to attack")
