


def right_rotate(value, bits):
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF

def right_shift(value, bits):
    return (value >> bits)


K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]
H = [
    0x6a09e667,0xbb67ae85,
    0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,
    0x1f83d9ab,0x5be0cd19
]


def sha256_padding(massage):
    original_byte_len = len(massage)
    original_bit_len = original_byte_len * 8

    massage += b"\x80"

    while (len(massage)*8) %512 != 448:
        massage += b"\x00"
    
    massage += original_bit_len.to_bytes(8, byteorder="big")

    return massage


def sha256(massage):
    massage = sha256_padding(massage)

    h = H.copy()

    for i in range(0, len(massage), 64):
        block = massage[i:i+64]
        w = []

        for j in range(16):
            w.append(int.from_bytes(block[j*4:(j+1)*4], byteorder="big"))
        
        for j in range(16, 64):
            s0 = right_rotate(w[j-15], 7) ^ right_rotate(w[j-15], 18) ^ (w[j-15] >> 3)
            s1 = right_rotate(w[j-2], 17) ^ right_rotate(w[j-2], 19) ^ (w[j-2] >> 10)
            w.append((w[j-16] + s0 + w[j-7] + s1) & 0xffffffff)

        a, b, c, d, e, f, g, h_temp, = h

        for j in range(64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h_temp + S1 + ch + K[j] + w[j]) & 0xffffffff

            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xffffffff

            h_temp = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        h = [
            (h[0] + a) & 0xffffffff,
            (h[1] + b) & 0xffffffff,
            (h[2] + c) & 0xffffffff,
            (h[3] + d) & 0xffffffff,
            (h[4] + e) & 0xffffffff,
            (h[5] + f) & 0xffffffff,
            (h[6] + g) & 0xffffffff,
            (h[7] + h_temp) & 0xffffffff
        ]

    return ''.join(f'{value:08x}' for value in h)


if __name__ == "__main__":
    msg = b"hello world"
    print("SHA-256", sha256(msg))