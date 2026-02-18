# CS 402 project 2
# Hyeonseo Lee, Bri Gonzalez, Kian Jennings

import sympy

# ==============================================
# Key Generation
# ==============================================
def keygen():
    p = sympy.randprime(2**511, 2** 512) # creating random prime numbers p and q
    q = sympy.randprime(2**511, 2** 512)
    while p == q:
        q = sympy.randprime(2**511, 2** 512)
    
    n = p * q
    T_n = (p-1) * (q-1)
    e = 65537
    d = pow(e, -1, T_n)

    return n, e, d

# ==============================================
# Block Size Calculation
# ==============================================

def max_block_size(n):
    return (n.bit_length() - 1) // 8

# ==============================================
# RSA Encryption and Decryption
# ==============================================
def RSA_encrypt(n, e, message):
    if not isinstance(message, str):
        raise ValueError("Message must be a string.")
    
    message_bytes = message.encode('utf-8')
    block_size = max_block_size(n)

    cipher_blocks = []

    if block_size <= 0:
        raise ValueError("Invalid modulus n.")

    if len(message_bytes) == 0:
        return []  # Return an empty list for an empty message
    
    # Split the message into blocks and encrypt each block
    blocks = []
    for i in range(0, len(message_bytes), block_size):
        blocks.append(message_bytes[i: i + block_size])

    for block in blocks:
        m = int.from_bytes(block, 'big')
        c = pow(m, e, n)
        cipher_blocks.append(c)

    return cipher_blocks

def RSA_decrypt(n, d, ciphertext):
    if not isinstance(ciphertext, list):
        raise ValueError("Ciphertext must be a list of integers.")
    
    block_size = max_block_size(n)
    message_bytes = bytearray()

    for c in ciphertext:
        if not isinstance(c, int):
            raise ValueError("Ciphertext must be a list of integers.")
        
        m = pow(c, d, n)
        block_bytes = m.to_bytes(block_size, 'big')
        block_bytes = block_bytes.lstrip(b"\x00") # Remove leading zeros

        message_bytes.extend(block_bytes)

    return message_bytes.decode('utf-8')

def main():
    message = "All Denison students should take CS402!"

    n, e, d = keygen()
    print(f"Public key (n, e): ({n}, {e})")
    print(f"Private key (n, d): ({n}, {d})")

    ciphertext = RSA_encrypt(n, e, message)
    print(f"Ciphertext: {ciphertext}")

    decrypted_message = RSA_decrypt(n, d, ciphertext)
    print(f"Decrypted message: {decrypted_message}")

if __name__ == "__main__":
    main()



