import hashlib
import string
import random

def md5(input: str) -> str:
    input = str(input)
    md5_hash = hashlib.md5(input.encode()).hexdigest()
    return md5_hash

def rand_base(length):
    base = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(base) for _ in range(length))

ALL_FUNCTIONS = {
    "md5": md5,
    "rand_base": rand_base
}