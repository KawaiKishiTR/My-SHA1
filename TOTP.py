import time
from HMAC_SHA1 import hmac_sha1

def int_to_bytes(val:int) -> bytes:
    return val.to_bytes(8, byteorder="big")

def truncate(hmac_result: bytes) -> int:
    offset = hmac_result[-1] & 0x0F
    part = hmac_result[offset:offset+4]
    bin_code = int.from_bytes(part, byteorder="big") &0x7fffffff
    return bin_code % 1000000

def totp(secret: bytes, interval=30) -> str:
    counter = int(time.time()) // interval
    counter_bytes = int_to_bytes(counter)
    hmac_result = hmac_sha1(secret, counter_bytes)
    code = truncate(hmac_result)
    return str(code).zfill(6)

if __name__ == "__main__":
    while True:
        secret = b"12345678901234567890"
        print("Current TOTP:", totp(secret))
        time.sleep(30)
        


