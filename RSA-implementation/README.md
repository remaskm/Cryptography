# CompleteRSA - RSA Encryption & Decryption with CRT Optimization

## Overview

**CompleteRSA** is a full-featured Java-based implementation of the RSA public-key cryptosystem. It supports encryption and decryption with various key sizes, provides CRT (Chinese Remainder Theorem) optimization for faster decryption, and incorporates secure prime generation using **Miller-Rabin** and **Fermat's** primality tests. It also includes a console-based interactive interface for experimenting with RSA operations.

This implementation is ideal for learning, testing, and demonstrating how RSA works in depth—from key generation to efficient modular arithmetic.

---

## Features

### RSA Support:

* Key sizes: **512, 1024, 2048, 3072, 4096 bits**
* Full RSA encryption and decryption support
* CRT optimization (\~4x decryption speedup)

### Primality Testing:

* Fermat's Little Theorem test
* Miller-Rabin probabilistic test
* Early rejection of small factors for speed

### Performance Enhancements:

* **Square-and-Multiply** modular exponentiation
* CRT-optimized decryption
* Efficient prime generation with custom loop and rejection handling

### Interactive Console:

* Choose key size
* Use existing keys or generate new ones
* Encrypt text or decimal messages
* Decrypt using standard or CRT-based methods
* View detailed step-by-step encryption and decryption processes

---

## Requirements

* Java Development Kit (JDK) 8 or higher
* Terminal or Java IDE (IntelliJ, Eclipse, etc.)

---

## Setup

### 1. Compile the Java file:

```bash
javac CompleteRSA.java
```

### 2. Run the program:

```bash
java CompleteRSA
```

---

## How It Works

### Step 1 – Key Selection:

* Choose RSA key size (512–4096 bits)
* Generate a new key pair or input your own components
* CRT parameters are generated automatically for optimization

### Step 2 – Encryption:

* Input your message (text or decimal number)
* Message is converted to BigInteger and encrypted as:
  `ciphertext = message^e mod n`

### Step 3 – Decryption:

* Choose standard decryption:
  `message = ciphertext^d mod n`
* Or use faster CRT decryption:

  * Compute partial decryptions `mp`, `mq`
  * Combine using CRT formula:
    `m = mq + q * ((mp - mq) * qInv mod p)`

---

## Example Usage

```plaintext
=== Complete RSA Implementation with CRT ===

Choose RSA key size (bits):
1) 512 bits (not secure for real use)
2) 1024 bits (minimum for testing)
3) 2048 bits (standard secure size)
Your choice: 3
Using RSA with 2048 bit key

Do you want to generate new keys or use existing ones? (G)enerate/(U)se: G
Generating 2048-bit RSA key pair with all optimizations...
Key generation completed in 4820 ms

Enter message to encrypt: HelloWorld

Choose input format:
1) Text (UTF-8)
2) Decimal number
Your choice: 1

=== ENCRYPTION RESULTS ===
Plaintext: 8752041279234
Ciphertext: 210398247923847239847...

Do you want to decrypt this message? (Y/N): Y

=== COMPARING DECRYPTION METHODS ===
Standard decryption: 8 ms
CRT decryption: 2 ms
Results match: true
CRT speedup: 4.00x faster
```

---

## Key Concepts

* **Modulus (`n`)** = `p × q`
* **Public exponent (`e`)** = typically `65537`
* **Private exponent (`d`)** = `e⁻¹ mod φ(n)`
* **CRT Optimization:**

  * `dp = d mod (p-1)`
  * `dq = d mod (q-1)`
  * `qInv = q⁻¹ mod p`

---

## Contributions

This project is open to improvements. Feel free to fork, enhance, or optimize the code further. Bug fixes and performance upgrades are welcome.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
