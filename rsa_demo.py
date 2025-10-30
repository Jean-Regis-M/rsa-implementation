import random
import math
import secrets
from typing import Tuple

class RSA:
    def __init__(self, key_size: int = 1024):
        """
        Initialize RSA with specified key size
        Common key sizes: 1024, 2048, 4096 bits
        """
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        self.n = None
        
    def is_prime(self, n: int, k: int = 128) -> bool:
        """
        Miller-Rabin primality test
        Returns True if n is probably prime, False if composite
        """
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False
            
        # Find r and d such that n-1 = 2^r * d
        r = 0
        d = n - 1
        while d % 2 == 0:
            d //= 2
            r += 1
            
        # Test k times
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
        """
        Generate a large prime number with specified number of bits
        """
        while True:
            # Generate random odd number with specified bits
            num = secrets.randbits(bits)
            num |= (1 << bits - 1) | 1  # Set highest and lowest bits to ensure correct size and odd
            
            if self.is_prime(num):
                return num
    
    def gcd(self, a: int, b: int) -> int:
        """
        Euclidean algorithm for Greatest Common Divisor
        """
        while b != 0:
            a, b = b, a % b
        return a
    
    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """
        Extended Euclidean Algorithm
        Returns (gcd, x, y) such that ax + by = gcd(a, b)
        """
        if a == 0:
            return b, 0, 1
            
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y
    
    def mod_inverse(self, a: int, m: int) -> int:
        """
        Compute modular inverse using extended Euclidean algorithm
        Returns x such that (a * x) % m = 1
        """
        gcd, x, _ = self.extended_gcd(a, m)
        
        if gcd != 1:
            raise ValueError(f"No modular inverse exists for {a} mod {m}")
            
        return x % m
    
    def generate_keys(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Generate RSA public and private keys
        Returns: (public_key, private_key) where:
            public_key = (e, n)
            private_key = (d, n)
        """
        # Generate two large distinct primes
        p_bits = self.key_size // 2
        q_bits = self.key_size - p_bits
        
        p = self.generate_large_prime(p_bits)
        q = self.generate_large_prime(q_bits)
        
        # Ensure p and q are distinct
        while p == q:
            q = self.generate_large_prime(q_bits)
        
        # Compute n = p * q
        n = p * q
        
        # Compute Euler's totient function φ(n) = (p-1)(q-1)
        phi = (p - 1) * (q - 1)
        
        # Choose public exponent e (commonly 65537)
        e = 65537
        while self.gcd(e, phi) != 1:
            e = random.randint(2, phi - 1)
        
        # Compute private exponent d = e^(-1) mod φ(n)
        d = self.mod_inverse(e, phi)
        
        self.public_key = (e, n)
        self.private_key = (d, n)
        self.n = n
        
        return self.public_key, self.private_key
    
    def encrypt(self, message: int, public_key: Tuple[int, int] = None) -> int:
        """
        Encrypt a message using RSA public key
        Message must be less than n
        """
        if public_key is None:
            if self.public_key is None:
                raise ValueError("No public key available")
            public_key = self.public_key
            
        e, n = public_key
        
        if message >= n:
            raise ValueError("Message too large for RSA encryption")
            
        # Encryption: ciphertext = message^e mod n
        ciphertext = pow(message, e, n)
        return ciphertext
    
    def decrypt(self, ciphertext: int, private_key: Tuple[int, int] = None) -> int:
        """
        Decrypt a ciphertext using RSA private key
        """
        if private_key is None:
            if self.private_key is None:
                raise ValueError("No private key available")
            private_key = self.private_key
            
        d, n = private_key
        
        # Decryption: message = ciphertext^d mod n
        message = pow(ciphertext, d, n)
        return message
    
    def encrypt_string(self, text: str, public_key: Tuple[int, int] = None) -> list:
        """
        Encrypt a string by converting to integers
        """
        if public_key is None:
            if self.public_key is None:
                raise ValueError("No public key available")
            public_key = self.public_key
            
        _, n = public_key
        max_bytes = (n.bit_length() - 1) // 8  # Maximum bytes we can encrypt
        
        # Convert string to bytes then to integer chunks
        text_bytes = text.encode('utf-8')
        chunks = []
        
        for i in range(0, len(text_bytes), max_bytes):
            chunk_bytes = text_bytes[i:i + max_bytes]
            chunk_int = int.from_bytes(chunk_bytes, 'big')
            chunks.append(chunk_int)
        
        # Encrypt each chunk
        encrypted_chunks = [self.encrypt(chunk, public_key) for chunk in chunks]
        return encrypted_chunks
    
    def decrypt_string(self, encrypted_chunks: list, private_key: Tuple[int, int] = None) -> str:
        """
        Decrypt encrypted chunks back to string
        """
        # Decrypt each chunk
        decrypted_chunks = [self.decrypt(chunk, private_key) for chunk in encrypted_chunks]
        
        # Convert integers back to bytes
        text_bytes = b''
        for chunk in decrypted_chunks:
            # Calculate number of bytes in the original chunk
            byte_length = (chunk.bit_length() + 7) // 8
            chunk_bytes = chunk.to_bytes(byte_length, 'big')
            text_bytes += chunk_bytes
        
        return text_bytes.decode('utf-8')

def demo_rsa():
    """
    Demonstration of RSA encryption and decryption
    """
    print("RSA Algorithm Demonstration")
    print("=" * 50)
    
    # Create RSA instance with 1024-bit keys
    rsa = RSA(key_size=1024)
    
    print("Generating RSA keys...")
    public_key, private_key = rsa.generate_keys()
    e, n = public_key
    d, _ = private_key
    
    print(f"Public Key (e, n):")
    print(f"  e = {e}")
    print(f"  n = {n}")
    print(f"\nPrivate Key (d, n):")
    print(f"  d = {d}")
    print(f"  n = {n}")
    
    # Test with a simple number
    print("\n" + "=" * 50)
    print("Testing with numeric message:")
    original_number = 42
    print(f"Original message: {original_number}")
    
    encrypted = rsa.encrypt(original_number)
    print(f"Encrypted: {encrypted}")
    
    decrypted = rsa.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    
    # Test with string message
    print("\n" + "=" * 50)
    print("Testing with string message:")
    message = "Hello, RSA Encryption!"
    print(f"Original message: '{message}'")
    
    encrypted_chunks = rsa.encrypt_string(message)
    print(f"Encrypted chunks: {encrypted_chunks}")
    
    decrypted_message = rsa.decrypt_string(encrypted_chunks)
    print(f"Decrypted message: '{decrypted_message}'")
    
    # Verify the process worked correctly
    print("\n" + "=" * 50)
    print("Verification:")
    print(f"Original == Decrypted: {message == decrypted_message}")
    print(f"Numeric test passed: {original_number == decrypted}")

def rsa_math_explanation():
    """
    Explain the mathematical foundation of RSA
    """
    print("\n" + "=" * 70)
    print("RSA MATHEMATICAL FOUNDATION")
    print("=" * 70)
    
    print("""
Key Generation:
1. Choose two large primes: p and q
2. Compute n = p × q
3. Compute φ(n) = (p-1) × (q-1)
4. Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
5. Compute d = e^(-1) mod φ(n)

Encryption: c = m^e mod n
Decryption: m = c^d mod n

Why it works (Euler's Theorem):
For any integer m coprime with n: m^φ(n) ≡ 1 mod n
Therefore: (m^e)^d = m^(e×d) = m^(k×φ(n) + 1) ≡ m mod n

Security relies on the difficulty of factoring large numbers n = p × q
""")

if __name__ == "__main__":
    # Run the demonstration
    demo_rsa()
    
    # Show mathematical explanation
    rsa_math_explanation()
    
    # Additional example with custom message
    print("\n" + "=" * 70)
    print("ADDITIONAL EXAMPLE")
    print("=" * 70)
    
    rsa2 = RSA(key_size=512)  # Smaller key for faster demonstration
    public_key, private_key = rsa2.generate_keys()
    
    test_message = "Secret message 123!"
    print(f"Testing with: '{test_message}'")
    
    encrypted = rsa2.encrypt_string(test_message)
    decrypted = rsa2.decrypt_string(encrypted)
    
    print(f"Encrypted successfully: {len(encrypted)} chunks")
    print(f"Decrypted correctly: '{decrypted}'")
    print(f"Match: {test_message == decrypted}")