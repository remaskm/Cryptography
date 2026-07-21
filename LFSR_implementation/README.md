# LFSR Key Generator Implementation

## Overview

LFSRKeyGenerator is a Java-based implementation of a Linear Feedback Shift Register (LFSR) key stream generator. It simulates the process of generating pseudorandom key streams for stream cipher applications. The program allows for the interactive setup of the LFSR, with features for customizing the seed, tap positions, and key stream generation. It also supports encryption and decryption using XOR operations with the generated key stream.

## Features

* **Configurable LFSR Setup**:

  * Customize the initial binary seed and feedback tap positions for the LFSR.
  * Supports automatic detection of optimal tap positions to maximize the period length of the key stream.

* **Key Stream Generation**:

  * Generate a pseudorandom key stream, validated to ensure cryptographic quality.
  * Visual feedback of the LFSR state during key generation, including clock cycles, feedback bit, and output bit.

* **Encryption and Decryption**:

  * Encrypt and decrypt messages (text or binary data) using XOR with the generated key stream.

* **Key Stream Validation**:

  * Ensures that the generated key stream does not consist entirely of zeros, and detects repetition in the sequence.

* **Encryption Types**:

  * Encrypt both text (ASCII) and binary data using the generated key stream.

## Requirements

* **Java Development Kit (JDK)**: Version 8 or higher.
* **IDE or Text Editor**: Optional, but recommended for code development.

## Setup

1. Clone this repository or download the source code.

2. Compile the Java file:

   ```bash
   javac LFSRKeyGenerator.java
   ```

3. Run the program:

   ```bash
   java LFSRKeyGenerator
   ```

---

## How It Works

### Start the Program:

* Upon running the program, the user is prompted to input a binary seed (at least 7 bits long with at least one '1').
* The user can either manually select tap positions or use the program's suggested optimal tap positions for a maximum-length sequence.

### Generate Key Stream:

* The program will generate a key stream based on the LFSR, outputting a detailed visualization of the internal state during the process.

### Encryption and Decryption:

* Once the key stream is generated, the user can encrypt or decrypt messages in both ASCII and binary formats using the XOR operation.
* The key stream is applied cyclically over the message to produce the encrypted output.
* The decryption process is symmetric, as XOR can be used for both encryption and decryption.

---

## Example Usage

Sample Session:

```
==============================================
             LFSR Key Generator
==============================================
This program generates a secure key stream
using a Linear Feedback Shift Register (LFSR),
a core component in stream cipher encryption.

Start by entering your seed below!
-----------------------------------------------
Enter seed (binary, at least 7 bits, must contain at least one '1'): 1010101
Do you want to manually choose taps? (yes/no): no
Using optimal taps: [6, 5, 4]
Generated Key Stream:
Clock Cycle | Register State          | Feedback Bit | Output Bit
-------------------------------------------------------
     0      | [1, 0, 1, 0, 1, 0, 1]   |      1       |      1
     1      | [1, 1, 0, 1, 0, 1, 0]   |      0       |      0
     2      | [0, 1, 1, 0, 1, 0, 1]   |      1       |      1
... (More cycles)

Generated Key Stream:
110011001010110011011...

Do you want to encrypt 
1-Text 
2-Binary Data? (1/2): 1
Enter plaintext message: Hello
Encrypted: Ï××¢°▓
Decrypted: Hello

Do you want to generate another key? (yes/no): no
```

---

## Contributions

Feel free to fork this repository and contribute enhancements or improvements. Issues and pull requests are welcome.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

