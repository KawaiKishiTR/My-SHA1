from SHA1 import sha1

def hmac_sha1(key: bytes, massage:bytes) -> bytes:
    block_size = 64
    
    if len(key) > block_size:
        key = bytes.fromhex(sha1(key))
    if len(key) < block_size:
        key = key + b"\x00" * (block_size - len(key))

    o_key_pad = bytes([b ^ 0x5C for b in key])
    i_key_pad = bytes([b ^ 0x36 for b in key])

    inner = sha1(i_key_pad + massage)
    return bytes.fromhex(sha1(o_key_pad + bytes.fromhex(inner)))

