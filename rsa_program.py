#!/usr/bin/env python3
import random
import math
import secrets
from typing import Tuple
import sys
import argparse

class RSA:
    def __init__(self, key_size: int = 1024):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        self.n = None
        
    def is_prime(self, n: int, k: int = 128) -> bool:
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False
            
        r = 0
        d = n - 1
        while d % 2 == 0:
            d //= 2
            r += 1
            
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
                
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
                
        return True
    
    def generate_large_prime(self, bits: int) -> int:
        while True:
            num = secrets.randbits(bits)
            num |= (1 << bits - 1) | 1
            
            if self.is_prime(num):
                return num
    
    def gcd(self, a: int, b: int) -> int:
        while b != 0:
            a, b = b, a % b
        return a
    
    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
            
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y
    
    def mod_inverse(self, a: int, m: int) -> int:
        gcd, x, _ = self.extended_gcd(a, m)
        
        if gcd != 1:
            raise ValueError(f"No modular inverse exists for {a} mod {m}")
            
        return x % m
    
    def generate_keys(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        p_bits = self.key_size // 2
        q_bits = self.key_size - p_bits
        
        p = self.generate_large_prime(p_bits)
        q = self.generate_large_prime(q_bits)
        
        while p == q:
            q = self.generate_large_prime(q_bits)
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        e = 65537
        while self.gcd(e, phi) != 1:
            e = random.randint(2, phi - 1)
        
        d = self.mod_inverse(e, phi)
        
        self.public_key = (e, n)
        self.private_key = (d, n)
        self.n = n
        
        return self.public_key, self.private_key
    
    def encrypt(self, message: int, public_key: Tuple[int, int] = None) -> int:
        if public_key is None:
            if self.public_key is None:
                raise ValueError("No public key available")
            public_key = self.public_key
            
        e, n = public_key
        
        if message >= n:
            raise ValueError("Message too large for RSA encryption")
            
        ciphertext = pow(message, e, n)
        return ciphertext
    
    def decrypt(self, ciphertext: int, private_key: Tuple[int, int] = None) -> int:
        if private_key is None:
            if self.private_key is None:
                raise ValueError("No private key available")
            private_key = self.private_key
            
        d, n = private_key
        
        message = pow(ciphertext, d, n)
        return message
    
    def encrypt_string(self, text: str, public_key: Tuple[int, int] = None) -> list:
        if public_key is None:
            if self.public_key is None:
                raise ValueError("No public key available")
            public_key = self.public_key
            
        _, n = public_key
        max_bytes = (n.bit_length() - 1) // 8
        
        text_bytes = text.encode('utf-8')
        chunks = []
        
        for i in range(0, len(text_bytes), max_bytes):
            chunk_bytes = text_bytes[i:i + max_bytes]
            chunk_int = int.from_bytes(chunk_bytes, 'big')
            chunks.append(chunk_int)
        
        encrypted_chunks = [self.encrypt(chunk, public_key) for chunk in chunks]
        return encrypted_chunks
    
    def decrypt_string(self, encrypted_chunks: list, private_key: Tuple[int, int] = None) -> str:
        decrypted_chunks = [self.decrypt(chunk, private_key) for chunk in encrypted_chunks]
        
        text_bytes = b''
        for chunk in decrypted_chunks:
            byte_length = (chunk.bit_length() + 7) // 8
            chunk_bytes = chunk.to_bytes(byte_length, 'big')
            text_bytes += chunk_bytes
        
        return text_bytes.decode('utf-8')

def main():
    parser = argparse.ArgumentParser(description='RSA Encryption/Decryption Tool')
    parser.add_argument('--key-size', type=int, default=1024, help='RSA key size in bits (default: 1024)')
    parser.add_argument('--message', type=str, help='Message to encrypt')
    parser.add_argument('--demo', action='store_true', help='Run demonstration')
    
    args = parser.parse_args()
    
    if args.demo or not args.message:
        run_demo(args.key_size)
    else:
        run_encryption(args.message, args.key_size)

def run_demo(key_size):
    print("🔐 RSA Algorithm Demonstration")
    print("=" * 50)
    
    rsa = RSA(key_size=key_size)
    
    print(f"Generating RSA-{key_size} keys...")
    public_key, private_key = rsa.generate_keys()
    e, n = public_key
    d, _ = private_key
    
    print(f"✓ Public Key generated")
    print(f"✓ Private Key generated")
    print(f"Modulus (n): {n}")
    print(f"Public exponent (e): {e}")
    
    # Test with number
    print("\n" + "-" * 50)
    print("Testing numeric encryption:")
    test_number = 12345
    encrypted = rsa.encrypt(test_number)
    decrypted = rsa.decrypt(encrypted)
    print(f"Original: {test_number}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print(f"✓ Success: {test_number == decrypted}")
    
    # Test with string
    print("\n" + "-" * 50)
    print("Testing string encryption:")
    test_message = "Hello from the terminal!"
    print(f"Original: '{test_message}'")
    
    encrypted_chunks = rsa.encrypt_string(test_message)
    decrypted_message = rsa.decrypt_string(encrypted_chunks)
    
    print(f"Encrypted into {len(encrypted_chunks)} chunks")
    print(f"Decrypted: '{decrypted_message}'")
    print(f"✓ Success: {test_message == decrypted_message}")

def run_encryption(message, key_size):
    print(f"🔐 Encrypting message with RSA-{key_size}")
    print("=" * 40)
    
    rsa = RSA(key_size=key_size)
    public_key, private_key = rsa.generate_keys()
    
    print(f"Message: '{message}'")
    
    # Encrypt
    encrypted_chunks = rsa.encrypt_string(message)
    print(f"Encrypted (as {len(encrypted_chunks)} chunks):")
    for i, chunk in enumerate(encrypted_chunks):
        print(f"  Chunk {i+1}: {chunk}")
    
    # Decrypt
    decrypted = rsa.decrypt_string(encrypted_chunks)
    print(f"Decrypted: '{decrypted}'")
    print(f"✓ Verification: {message == decrypted}")
    
    # Show keys (for educational purposes)
    e, n = public_key
    d, _ = private_key
    print(f"\nKeys (for reference):")
    print(f"Public: (e={e}, n={n})")
    print(f"Private: (d={d}, n={n})")

if __name__ == "__main__":
    main()