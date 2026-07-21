# AESManual - Advanced Encryption Standard (AES) Implementation

## Overview

AESManual is a Java-based manual implementation of the **Advanced Encryption Standard (AES)** algorithm. It supports AES-128, AES-192, and AES-256 encryption/decryption and allows the user to interactively input and process plaintext in various formats (ASCII, Binary, Hexadecimal). This implementation simulates AES encryption and decryption in its full form, demonstrating the core operations like SubBytes, ShiftRows, MixColumns, and Key Expansion.

## Features

* **Supports AES Variants:**

  * AES-128 (128-bit key, 10 rounds)
  * AES-192 (192-bit key, 12 rounds)
  * AES-256 (256-bit key, 14 rounds)

* **Flexible Input Formats:**

  * ASCII
  * Binary
  * Hexadecimal

* **Interactive Console:**

  * Input plaintext in various formats and see the binary/hexadecimal equivalents.
  * Generate or manually enter an encryption key.
  * Encrypt and decrypt the message with visual feedback.
  * Option to view encryption steps and process.

* **Key Expansion:**

  * Key expansion is performed for AES variants, generating round keys for encryption and decryption.

* **Encryption and Decryption Process:**

  * Supports both encryption and decryption of data with a step-by-step breakdown of operations.

* **Random Key Generation:**

  * If the user opts for a random key, the program automatically generates one, ensuring that each encryption is unique.

## Requirements

* **Java Development Kit (JDK):** Version 8 or higher
* **IDE or Text Editor** (Optional but recommended for code development)

## Setup

1. Clone this repository or download the source code.

2. Compile the Java file:

   ```bash
   javac AESManual.java
   ```

3. Run the program:

   ```bash
   java AESManual
   ```

## How It Works

1. **Start the Program:**

   * The user is prompted to enter the plaintext and select the format (ASCII, Binary, Hexadecimal).

2. **Key Setup:**

   * The user is then asked to select the AES variant (AES-128, AES-192, or AES-256) and provide a key (manually or via random generation).

3. **Encryption Process:**

   * The plaintext is converted into binary, and the AES algorithm is applied to it. The encryption process includes all stages of AES: SubBytes, ShiftRows, MixColumns, and AddRoundKey.
   * The encrypted message is displayed in both binary and hexadecimal formats.

4. **Decryption Process:**

   * The user can decrypt the encrypted message, reversing the encryption process.

5. **View the Encryption Process:**

   * The program allows the user to view a detailed step-by-step breakdown of the AES encryption process.

## Example Usage

### Sample Session:

```
AES Encryption and Decryption Implementation
-------------------------------------------
Do you want to enter (1) Plaintext (ASCII), (2) Binary, or (3) Hexadecimal? 1
Enter your message (will be truncated to 128 bits/16 bytes if needed): HelloWorld
Binary representation (128 bits): 0100100001100101011011000110110001101111001000000101011101101111011101000110110001100100
Choose AES variant:
1) AES-128 (128-bit key, 10 rounds)
2) AES-192 (192-bit key, 12 rounds)
3) AES-256 (256-bit key, 14 rounds)
Your choice: 1
Using AES-128 with 10 rounds
Enter key manually? (yes/no): no
Generated random key: 63C2D0B1F89F0047A1B6C0F9C9F5A67D
Key (hex): 63C2D0B1F89F0047A1B6C0F9C9F5A67D
Key (binary): 011000111100001011010000101100011111100010011111000000010010001110100110110000001111100111001111010011110101101111011101
*** ENCRYPTED MESSAGE ***
Binary: 010100111000011011110001101010101111101101101011101000110011110111111100011011110111011111000100011100000100000101100110111000
Hexadecimal: 4F9B6CFAF8B6C0E9E3436E6A7E2AC16F
```

### Key Points:

* The program automatically truncates or pads input to fit 128 bits.
* A random key is generated if the user chooses not to manually input one.
* The encryption and decryption process happens in real-time, with results displayed in both binary and hexadecimal formats.

## Contributions

Feel free to fork this repository and contribute enhancements or improvements. Issues and pull requests are welcome.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.