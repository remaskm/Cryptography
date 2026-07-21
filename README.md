# Cryptography — Algorithm Implementations & Attacks

From-scratch Java implementations of core symmetric and asymmetric cryptographic algorithms, built to understand each cipher at the level of its actual operations (permutations, S-boxes, modular arithmetic, feedback registers) rather than by calling a library. Includes a practical cryptanalytic attack demonstrating *why* naive multiple-encryption doesn't give the security gain it appears to.

## Contents

| Folder | Algorithm | Notes |
|---|---|---|
| [`DES_implementation`](./DES_implementation) | DES | Manual implementation — key generation, initial/final permutation, S-box substitution, and the full Feistel network. Includes a **Meet-in-the-Middle attack demonstration against Triple DES**, showing why simply chaining DES encryptions multiple times doesn't multiply keyspace security the way it intuitively seems to. |
| [`AES_Implementation`](./AES_Implementation) | AES | Key management plus encryption/decryption. |
| [`RSA-implementation`](./RSA-implementation) | RSA | Full key generation, encryption, decryption, and **CRT (Chinese Remainder Theorem) optimization** for faster decryption. Secure prime generation via **Miller-Rabin** and **Fermat** primality testing. Console-based interactive interface for experimenting with different key sizes (512/1024/2048-bit). |
| [`Elgamal-cryptosystem`](./Elgamal-cryptosystem) | ElGamal | Asymmetric encryption based on the discrete logarithm problem. |
| [`LFSR_implementation`](./LFSR_implementation) | LFSR | Linear Feedback Shift Register models for stream cipher key/keystream generation. |

## Why the Meet-in-the-Middle attack matters

Triple DES was designed on the assumption that applying DES three times with independent keys multiplies the effective keyspace. In practice, a Meet-in-the-Middle attack against the two-key (2DES) construction reduces the attacker's work from a brute-force `2^112` down to roughly `2^57` — encrypting from the plaintext side and decrypting from the ciphertext side, then looking for a match in the middle, rather than trying every key combination. This is the actual mathematical reason 3DES uses three independent keys (or an encrypt-decrypt-encrypt structure) instead of just two, and why it's now considered legacy compared to AES.

## Running the code

Each folder is a standalone Java project:

```bash
cd RSA-implementation
javac *.java
java Main   # entry point name varies per folder — see individual folder for the class containing main()
```

No external dependencies — standard Java only (`java.math.BigInteger` is used for RSA/ElGamal's large-number arithmetic).

## Disclaimer

These are educational implementations built to understand how each algorithm works internally. They are **not** hardened, side-channel-resistant, or suitable for production use — use a vetted library (e.g. `javax.crypto`, Bouncy Castle) for anything real.
