

def left_rotate(value, bits):
    return ((value << bits) | (value >> (32-bits))) & 0xffffffff

def sha1_padding(massage):
    original_byte_len = len(massage)
    original_bit_len = original_byte_len*8

    massage += b"\x80"

    while (len(massage)*8) %512 != 448:
        massage += b"\x00"

    massage += original_bit_len.to_bytes(8, byteorder="big")

    return massage

def sha1(massage):
    massage = sha1_padding(massage)

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    for i in range(0, len(massage), 64):
        block = massage[i:i+64]
        w = []

        for j in range(16):
            w.append(int.from_bytes(block[j*4:(j+1)*4], byteorder="big"))
        

        for j in range(16, 80):
            val = w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]
            w.append(left_rotate(val, 1))

        a, b, c, d, e = h0, h1, h2, h3, h4

        for j in range(80):
            if 0 <= j <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            
            temp = (left_rotate(a, 5) + f + e + k + w[j]) & 0xffffffff
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp
        
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
    
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)













if __name__ == "__main__":
    msg = b"hello world"
    print("SHA-1", sha1(msg))

