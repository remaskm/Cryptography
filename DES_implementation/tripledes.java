import java.util.*;

/**
 * TripleDESAndMITM.java
 *
 * This program implements:
 *   1. Single DES (Data Encryption Standard) — the core cipher used as a building block
 *   2. Triple DES (3DES/TDEA) in EDE mode — runs DES three times with three different keys
 *   3. Meet-in-the-Middle (MITM) attack — a cryptanalytic attack against Triple DES
 *
 * ─────────────────────────────────────────────────────────
 *  SECTION 1 — SINGLE DES
 * ─────────────────────────────────────────────────────────
 *
 * DES is a symmetric block cipher that:
 *   - Takes a 64-bit (8 character) plaintext block
 *   - Takes a 64-bit (8 character) key (only 56 bits are effective; 8 are parity bits)
 *   - Produces a 64-bit ciphertext block
 *   - Uses a Feistel network with 16 rounds
 *
 * High-level DES encryption flow:
 *
 *   Plaintext (64 bits)
 *       │
 *       ▼
 *   Initial Permutation (IP)         ← scrambles the bit order
 *       │
 *       ▼
 *   Split into L0 (left 32 bits) and R0 (right 32 bits)
 *       │
 *       ▼
 *   ┌── Feistel Rounds × 16 ──────────────────────┐
 *   │  L_i = R_(i-1)                              │
 *   │  R_i = L_(i-1) XOR f(R_(i-1), K_i)         │
 *   │                                             │
 *   │  f() = Expand → XOR with round key →       │
 *   │         S-Box substitution → P permutation  │
 *   └─────────────────────────────────────────────┘
 *       │
 *       ▼
 *   Swap final halves → R16 + L16
 *       │
 *       ▼
 *   Final Permutation (FP/IP⁻¹)      ← inverse of IP
 *       │
 *       ▼
 *   Ciphertext (64 bits)
 *
 * Key schedule:
 *   - PC1 reduces 64-bit key → 56 bits (removes parity)
 *   - Split into C and D halves (28 bits each)
 *   - Each round: left-shift C and D by SHIFTS[i], then PC2 selects 48 bits → round key K_i
 */
public class TripleDESAndMITM {

    // ─────────────────────────────────────────────────────────
    // DES LOOKUP TABLES
    // ─────────────────────────────────────────────────────────

    /**
     * Initial Permutation (IP).
     * Applied to the 64-bit plaintext block before the first Feistel round.
     * Rearranges bit positions to provide an initial diffusion step.
     * Table is 1-indexed: IP[0]=58 means bit 58 of the input becomes bit 1 of the output.
     */
    private static final int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17,  9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    /**
     * Final Permutation (FP), also called IP⁻¹.
     * Applied after the 16th round swap (R16+L16) to produce the final ciphertext.
     * FP is the exact inverse of IP — applying IP then FP returns the original bit order.
     */
    private static final int[] FP = {
            40,  8, 48, 16, 56, 24, 64, 32,
            39,  7, 47, 15, 55, 23, 63, 31,
            38,  6, 46, 14, 54, 22, 62, 30,
            37,  5, 45, 13, 53, 21, 61, 29,
            36,  4, 44, 12, 52, 20, 60, 28,
            35,  3, 43, 11, 51, 19, 59, 27,
            34,  2, 42, 10, 50, 18, 58, 26,
            33,  1, 41,  9, 49, 17, 57, 25
    };

    /**
     * Expansion Permutation (E).
     * Expands the 32-bit right half to 48 bits inside the Feistel function.
     * Some bits are repeated so the result can be XORed with the 48-bit round key.
     * The expansion also makes every output bit depend on 2 input bits, increasing diffusion.
     */
    private static final int[] E = {
            32,  1,  2,  3,  4,  5,
             4,  5,  6,  7,  8,  9,
             8,  9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32,  1
    };

    /**
     * Permutation function (P-box).
     * Applied to the 32-bit output of the 8 S-boxes inside the Feistel function.
     * Spreads the output of each S-box across multiple S-boxes in the next round,
     * ensuring diffusion — a change in one bit affects many bits going forward.
     */
    private static final int[] P = {
            16,  7, 20, 21, 29, 12, 28, 17,
             1, 15, 23, 26,  5, 18, 31, 10,
             2,  8, 24, 14, 32, 27,  3,  9,
            19, 13, 30,  6, 22, 11,  4, 25
    };

    /**
     * S-Boxes (Substitution Boxes) — the only non-linear part of DES.
     * There are 8 S-boxes; each takes 6 bits and outputs 4 bits.
     * Non-linearity is critical: it prevents the cipher from being broken with linear algebra.
     *
     * How to look up a value in SBOX[i]:
     *   - Given 6-bit input: b0 b1 b2 b3 b4 b5
     *   - row = (b0 b5) as a 2-bit number  → selects one of 4 rows
     *   - col = (b1 b2 b3 b4) as a 4-bit number → selects one of 16 columns
     *   - output = SBOX[i][row][col]  (a 4-bit value, 0–15)
     */
    private static final int[][][] SBOX = {
            { {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},  {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                    {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},  {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13} },
            { {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},  {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                    {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},  {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9} },
            { {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},  {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                    {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},  {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12} },
            { {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},  {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                    {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},  {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14} },
            { {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},  {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                    {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},  {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3} },
            { {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},  {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                    {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},  {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13} },
            { {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},  {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                    {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},  {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12} },
            { {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},  {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                    {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},  {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11} }
    };

    /**
     * Permuted Choice 1 (PC1) — Key schedule step 1.
     * Selects 56 of the 64 key bits, discarding the 8 parity bits (positions 8,16,24,...,64).
     * Output is split into C0 (bits 1–28) and D0 (bits 29–56) for the key schedule.
     */
    private static final int[] PC1 = {
            57, 49, 41, 33, 25, 17,  9,
             1, 58, 50, 42, 34, 26, 18,
            10,  2, 59, 51, 43, 35, 27,
            19, 11,  3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
             7, 62, 54, 46, 38, 30, 22,
            14,  6, 61, 53, 45, 37, 29,
            21, 13,  5, 28, 20, 12,  4
    };

    /**
     * Permuted Choice 2 (PC2) — Key schedule step 2.
     * After left-rotating C and D halves for each round, PC2 selects 48 of the 56 bits
     * to form the round key K_i. Different bits are chosen each round, contributing to
     * the avalanche effect (changing one key bit affects many round keys).
     */
    private static final int[] PC2 = {
            14, 17, 11, 24,  1,  5,
             3, 28, 15,  6, 21, 10,
            23, 19, 12,  4, 26,  8,
            16,  7, 27, 20, 13,  2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
    };

    /**
     * Left shift schedule for the key schedule.
     * Each entry indicates how many positions to left-rotate C and D
     * before generating round key K_i. Rounds 1, 2, 9, 16 shift by 1;
     * all other rounds shift by 2. Total shifts = 28, completing a full rotation.
     */
    private static final int[] SHIFTS = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};


    // ─────────────────────────────────────────────────────────
    // STATE SHARED BETWEEN PART 1 AND PART 2
    // ─────────────────────────────────────────────────────────

    // These are populated during Part 1 (3DES encryption) so Part 2 (MITM)
    // can reuse the same plaintext/ciphertext pairs without re-entering them.
    static List<String> lastPlainBlocks  = null;
    static List<String> lastCipherBlocks = null;
    static String lastK1 = null, lastK2 = null, lastK3 = null;


    // ─────────────────────────────────────────────────────────
    // CORE DES UTILITY METHODS
    // ─────────────────────────────────────────────────────────

    /**
     * Applies a permutation table to a binary string.
     *
     * For each entry `i` in the table, takes bit at position (i-1) from `input`
     * (tables are 1-indexed) and appends it to the result.
     *
     * Used for: IP, FP, E, P, PC1, PC2.
     *
     * @param input  Binary string to permute
     * @param table  Permutation table (1-indexed bit positions)
     * @return       Permuted binary string (length = table.length)
     */
    static String permute(String input, int[] table) {
        StringBuilder sb = new StringBuilder();
        for (int i : table) sb.append(input.charAt(i - 1));
        return sb.toString();
    }

    /**
     * Bitwise XOR of two equal-length binary strings.
     * Result bit is '0' if both bits match, '1' if they differ.
     * Used to mix the round key with the expanded right half inside f(),
     * and to combine f(R, K) with the left half in each Feistel round.
     */
    static String xor(String a, String b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < a.length(); i++)
            sb.append(a.charAt(i) == b.charAt(i) ? '0' : '1');
        return sb.toString();
    }

    /**
     * The Feistel function f(R, K) — silent version (no console output).
     *
     * Steps:
     *   1. Expand R from 32 → 48 bits using table E (some bits repeated)
     *   2. XOR the expanded R with the 48-bit round key K
     *   3. Split the 48-bit result into 8 groups of 6 bits
     *   4. Pass each 6-bit group through its S-box → 4-bit output
     *   5. Concatenate all 8 × 4-bit outputs → 32 bits
     *   6. Apply permutation P to spread the S-box outputs (diffusion)
     *
     * @param right  32-bit right half of the Feistel block
     * @param key    48-bit round key
     * @return       32-bit output of f()
     */
    static String feistelQuiet(String right, String key) {
        // Step 1: Expand 32-bit R to 48 bits
        String expanded = permute(right, E);

        // Step 2: XOR with round key — mixes key material into the data
        String xored = xor(expanded, key);

        StringBuilder sOut = new StringBuilder();

        // Steps 3–4: Process each of the 8 six-bit groups through an S-box
        for (int i = 0; i < 8; i++) {
            String block = xored.substring(i * 6, (i + 1) * 6);

            // Row: first and last bits of the 6-bit block (e.g., b0 and b5)
            int row = Integer.parseInt("" + block.charAt(0) + block.charAt(5), 2);

            // Column: middle 4 bits (b1 b2 b3 b4)
            int col = Integer.parseInt(block.substring(1, 5), 2);

            // Look up the 4-bit S-box output
            int val = SBOX[i][row][col];

            // Convert to 4-bit binary, left-pad with zeros
            sOut.append(String.format("%4s", Integer.toBinaryString(val)).replace(' ', '0'));
        }

        // Step 6: Apply P-box permutation for diffusion
        return permute(sOut.toString(), P);
    }

    /**
     * The Feistel function f(R, K) — verbose version (prints each step).
     * Identical logic to feistelQuiet(); used only when showing encryption details to the user.
     */
    static String feistelVerbose(String right, String key) {
        String expanded = permute(right, E);
        System.out.println("Expanded R (48-bit): " + expanded);

        String xored = xor(expanded, key);
        System.out.println("After XOR with key : " + xored);

        StringBuilder sOut = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            String block = xored.substring(i * 6, (i + 1) * 6);
            int row = Integer.parseInt("" + block.charAt(0) + block.charAt(5), 2);
            int col = Integer.parseInt(block.substring(1, 5), 2);
            int val = SBOX[i][row][col];
            sOut.append(String.format("%4s", Integer.toBinaryString(val)).replace(' ', '0'));
        }

        System.out.println("      After S-Box subst. : " + sOut);
        String result = permute(sOut.toString(), P);
        System.out.println("      After permutation P : " + result);
        return result;
    }

    /**
     * Key Schedule — generates the 16 round keys from a single 64-bit key.
     *
     * Steps:
     *   1. Apply PC1: 64 bits → 56 bits (strips 8 parity bits)
     *   2. Split into C (left 28 bits) and D (right 28 bits)
     *   3. For each of the 16 rounds:
     *        a. Left-rotate C and D by SHIFTS[i] positions
     *        b. Apply PC2 to C+D (56 bits → 48 bits) → round key K_i
     *
     * Decryption uses the same 16 keys but in reverse order (K16 → K1).
     *
     * @param binaryKey  64-bit key as a binary string
     * @return           Array of 16 round keys (each 48 bits)
     */
    static String[] generateKeys(String binaryKey) {
        // Step 1: Remove parity bits, keep only the 56 effective key bits
        String pk = permute(binaryKey, PC1);

        // Step 2: Split the 56-bit key into two 28-bit halves
        String C = pk.substring(0, 28);
        String D = pk.substring(28);

        String[] keys = new String[16];

        for (int i = 0; i < 16; i++) {
            // Step 3a: Left-rotate each half by the scheduled number of positions
            C = C.substring(SHIFTS[i]) + C.substring(0, SHIFTS[i]);
            D = D.substring(SHIFTS[i]) + D.substring(0, SHIFTS[i]);

            // Step 3b: Select 48 bits from the 56-bit combined C+D → round key
            keys[i] = permute(C + D, PC2);
        }

        return keys;
    }

    /**
     * Core DES block cipher — silent version.
     *
     * Encrypts or decrypts exactly one 64-bit block using pre-generated round keys.
     *
     * Encryption (encrypt=true):  applies round keys K1 → K16
     * Decryption (encrypt=false): applies round keys K16 → K1
     *   (DES decryption is identical to encryption but with the key order reversed —
     *    a consequence of the Feistel structure.)
     *
     * @param block64    64-bit input block (binary string)
     * @param roundKeys  The 16 round keys from generateKeys()
     * @param encrypt    true = encrypt, false = decrypt
     * @return           64-bit output block (binary string)
     */
    static String desCore(String block64, String[] roundKeys, boolean encrypt) {
        // Apply the initial permutation to scramble the input bit order
        String permuted = permute(block64, IP);

        // Split into left and right 32-bit halves
        String left  = permuted.substring(0, 32);
        String right = permuted.substring(32);

        // Run 16 Feistel rounds
        for (int i = 0; i < 16; i++) {
            // Choose key index: forward (0..15) for encryption, reverse (15..0) for decryption
            int ki = encrypt ? i : (15 - i);

            String tmp = right;                            // save current right half
            right = xor(left, feistelQuiet(right, roundKeys[ki])); // R_i = L_(i-1) XOR f(R_(i-1), K_i)
            left  = tmp;                                   // L_i = R_(i-1)  (simple swap)
        }

        // After round 16, perform the final swap (R16+L16, NOT L16+R16) then apply FP
        return permute(right + left, FP);
    }

    /**
     * Core DES block cipher — verbose version (prints every round).
     * Same logic as desCore(); used only for displaying detailed step-by-step output.
     */
    static String desCoreVerbose(String block64, String[] roundKeys, boolean encrypt, String keyLabel) {
        System.out.println("  Starting DES " + (encrypt ? "encryption" : "decryption")
                + " with key " + keyLabel);
        String permuted = permute(block64, IP);
        System.out.println("  After IP        : " + permuted);
        String left  = permuted.substring(0, 32);
        String right = permuted.substring(32);
        System.out.println("  L0: " + left);
        System.out.println("  R0: " + right);
        for (int i = 0; i < 16; i++) {
            int ki = encrypt ? i : (15 - i);
            int kn = encrypt ? (i + 1) : (16 - i);
            System.out.println("\n  Round " + (i + 1) + " (using round key K" + kn + "):");
            String f   = feistelVerbose(right, roundKeys[ki]);
            System.out.println("    f(R" + i + ", K" + kn + ") = " + f);
            String tmp = right;
            right = xor(left, f);
            System.out.println("    R" + (i + 1) + " = " + right);
            left  = tmp;
            System.out.println("    L" + (i + 1) + " = " + left);
        }
        String combined = right + left;
        System.out.println("\n  Pre-output (R16L16): " + combined);
        String result = permute(combined, FP);
        System.out.println("  After FP           : " + result);
        return result;
    }


    // ─────────────────────────────────────────────────────────
    // ENCODING / DECODING HELPERS
    // ─────────────────────────────────────────────────────────

    /** Converts a text string to its binary representation (8 bits per ASCII character). */
    static String stringToBinary(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray())
            sb.append(String.format("%8s", Integer.toBinaryString(c)).replace(' ', '0'));
        return sb.toString();
    }

    /** Converts a binary string back to a text string (one character per 8 bits). */
    static String binaryToString(String bin) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i + 8 <= bin.length(); i += 8)
            sb.append((char) Integer.parseInt(bin.substring(i, i + 8), 2));
        return sb.toString();
    }

    /** Converts a hexadecimal string to a binary string (4 bits per hex digit). */
    static String hexToBinary(String hex) {
        StringBuilder sb = new StringBuilder();
        for (char c : hex.toCharArray())
            sb.append(String.format("%4s",
                    Integer.toBinaryString(Integer.parseInt("" + c, 16))).replace(' ', '0'));
        return sb.toString();
    }

    /** Converts a binary string to an uppercase hexadecimal string (4 bits per hex digit). */
    static String binaryToHex(String bin) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bin.length(); i += 4)
            sb.append(Integer.toHexString(
                    Integer.parseInt(bin.substring(i, i + 4), 2)).toUpperCase());
        return sb.toString();
    }

    /**
     * Splits an arbitrarily long binary string into 64-bit blocks.
     * If the last block is shorter than 64 bits, it is zero-padded on the right.
     * DES operates on fixed 64-bit blocks, so this handles messages of any length.
     */
    static List<String> splitIntoBlocks(String binaryText) {
        List<String> blocks = new ArrayList<>();
        for (int i = 0; i < binaryText.length(); i += 64) {
            String block = binaryText.substring(i, Math.min(i + 64, binaryText.length()));
            while (block.length() < 64) block += "0"; // zero-pad the last block if needed
            blocks.add(block);
        }
        return blocks;
    }

    /** Prompts the user for a key and loops until exactly 8 characters are entered. */
    static String readValidKey(Scanner sc, String keyName) {
        while (true) {
            System.out.print("Enter " + keyName + " (exactly 8 characters): ");
            String key = sc.nextLine();
            if (key.length() == 8) return key;
            System.out.println("  ERROR: Key must be exactly 8 characters."
                    + " You entered " + key.length() + " character(s). Please try again.");
        }
    }

    /** Returns true if the user typed "yes" or "y" (case-insensitive). */
    static boolean isYes(String s) {
        s = s.trim().toLowerCase();
        return s.equals("yes") || s.equals("y");
    }


    // ─────────────────────────────────────────────────────────
    // SECTION 2 — TRIPLE DES (3DES / TDEA)
    // ─────────────────────────────────────────────────────────
    //
    // Triple DES applies single DES three times in EDE (Encrypt-Decrypt-Encrypt) mode:
    //
    //   Encryption:  C = E_K3( D_K2( E_K1( P ) ) )
    //   Decryption:  P = D_K1( E_K2( D_K3( C ) ) )
    //
    // Why EDE?
    //   - When K1 = K2 = K3, the middle Decrypt undoes the first Encrypt,
    //     giving plain DES — backward compatibility with single DES systems.
    //   - Three independent keys gives an effective key length of 168 bits
    //     (3 × 56), dramatically more secure than single DES (56 bits).
    //
    // Why not just Double DES (E_K2(E_K1(P)))?
    //   - Double DES is vulnerable to the Meet-in-the-Middle attack (see Section 3),
    //     which reduces its effective security to only ~57 bits.
    //   - Triple DES forces an attacker to search 2^112 pairs instead of 2^57.
    // ─────────────────────────────────────────────────────────

    /**
     * Encrypts one 64-bit block with Triple DES (EDE mode) — silent.
     *
     * Flow: plaintext → E_K1 → D_K2 → E_K3 → ciphertext
     *
     * @param b64  64-bit plaintext block (binary string)
     * @param rk1  16 round keys for K1 (used for DES encryption)
     * @param rk2  16 round keys for K2 (used for DES decryption)
     * @param rk3  16 round keys for K3 (used for DES encryption)
     * @return     64-bit ciphertext block (binary string)
     */
    static String tripleDesEncryptBlock(String b64, String[] rk1, String[] rk2, String[] rk3) {
        // Step 1: Encrypt with K1
        String afterK1 = desCore(b64, rk1, true);
        // Step 2: Decrypt with K2  (the "D" in EDE)
        String afterK2 = desCore(afterK1, rk2, false);
        // Step 3: Encrypt with K3
        return desCore(afterK2, rk3, true);
    }

    /**
     * Decrypts one 64-bit block with Triple DES (EDE mode) — silent.
     *
     * Flow: ciphertext → D_K3 → E_K2 → D_K1 → plaintext
     * (Exact reverse of encryption: each step inverted, order reversed.)
     *
     * @param b64  64-bit ciphertext block (binary string)
     * @param rk1  16 round keys for K1 (used for DES decryption)
     * @param rk2  16 round keys for K2 (used for DES encryption)
     * @param rk3  16 round keys for K3 (used for DES decryption)
     * @return     64-bit plaintext block (binary string)
     */
    static String tripleDesDecryptBlock(String b64, String[] rk1, String[] rk2, String[] rk3) {
        String afterK3 = desCore(b64,     rk3, false); // Step 1: Decrypt with K3
        String afterK2 = desCore(afterK3, rk2, true);  // Step 2: Encrypt with K2
        return           desCore(afterK2, rk1, false);  // Step 3: Decrypt with K1
    }

    /**
     * Triple DES encryption — verbose version (prints every DES sub-step).
     * Shows the three DES passes (E/D/E) in sequence for block 1.
     */
    static String tripleDesEncryptVerbose(String b64, String[] rk1, String[] rk2, String[] rk3) {
        System.out.println("\n  ===== Step 1 of 3 : Encrypt with K1 =====");
        String s1 = desCoreVerbose(b64, rk1, true,  "K1");
        System.out.println("\n  ===== Step 2 of 3 : Decrypt with K2 =====");
        String s2 = desCoreVerbose(s1,  rk2, false, "K2");
        System.out.println("\n  ===== Step 3 of 3 : Encrypt with K3 =====");
        return     desCoreVerbose(s2,  rk3, true,  "K3");
    }

    /**
     * Triple DES decryption — verbose version (prints every DES sub-step).
     */
    static String tripleDesDecryptVerbose(String b64, String[] rk1, String[] rk2, String[] rk3) {
        System.out.println("\n  ===== Step 1 of 3 : Decrypt with K3 =====");
        String s1 = desCoreVerbose(b64, rk3, false, "K3");
        System.out.println("\n  ===== Step 2 of 3 : Encrypt with K2 =====");
        String s2 = desCoreVerbose(s1,  rk2, true,  "K2");
        System.out.println("\n  ===== Step 3 of 3 : Decrypt with K1 =====");
        return     desCoreVerbose(s2,  rk1, false, "K1");
    }

    /**
     * Part 1 — Interactive menu for Triple DES encryption and decryption.
     * Accepts plaintext or hex input, three 8-character keys, and optionally
     * prints round keys and detailed step-by-step output.
     * Results are saved to static fields so Part 2 can reuse them.
     */
    static void runPartOne(Scanner sc) {
        System.out.println("\nTriple DES Encryption and Decryption");
        System.out.println("-------------------------------------");

        // Choose input format: plaintext or hex
        System.out.print("Do you want to enter (1) Plaintext or (2) Hexadecimal? ");
        int choice = 0;
        while (choice != 1 && choice != 2) {
            try { choice = Integer.parseInt(sc.nextLine().trim()); }
            catch (NumberFormatException e) { choice = 0; }
            if (choice != 1 && choice != 2)
                System.out.print("  Please enter 1 (Plaintext) or 2 (Hexadecimal): ");
        }

        String binaryAll, originalInput;

        if (choice == 1) {
            System.out.print("Enter plaintext (any size): ");
            String pt = sc.nextLine();
            originalInput = pt;
            binaryAll     = stringToBinary(pt);
            System.out.println("Binary representation: " + binaryAll);
        } else {
            System.out.print("Enter hexadecimal (must be a multiple of 16 hex digits): ");
            String hex = sc.nextLine().trim();
            while (hex.length() % 16 != 0) hex += "0"; // pad to full blocks
            originalInput = hex;
            binaryAll     = hexToBinary(hex);
            System.out.println("Binary representation: " + binaryAll);
        }

        // Split the full binary input into 64-bit blocks for block-cipher processing
        List<String> blocks = splitIntoBlocks(binaryAll);
        int n = blocks.size();
        if (n == 1) {
            System.out.println("Input fits in one 64-bit block.");
        } else {
            System.out.println("Input spans " + n + " blocks of 64 bits"
                    + " (last block zero-padded to 64 bits if needed).");
        }

        // Read three independent 8-character keys
        String k1Str = readValidKey(sc, "K1");
        String k2Str = readValidKey(sc, "K2");
        String k3Str = readValidKey(sc, "K3");

        // Convert keys to binary and generate their 16 round keys each
        String bk1 = stringToBinary(k1Str);
        String bk2 = stringToBinary(k2Str);
        String bk3 = stringToBinary(k3Str);
        System.out.println("Binary K1: " + bk1);
        System.out.println("Binary K2: " + bk2);
        System.out.println("Binary K3: " + bk3);

        String[] rk1 = generateKeys(bk1);
        String[] rk2 = generateKeys(bk2);
        String[] rk3 = generateKeys(bk3);

        System.out.println("\n--- Round Keys Generated ---");
        System.out.print("Do you want to see the round keys? (yes/no): ");
        if (isYes(sc.nextLine())) {
            String[][]  allRK    = {rk1, rk2, rk3};
            String[]    labels   = {"K1", "K2", "K3"};
            for (int k = 0; k < 3; k++) {
                System.out.println("  " + labels[k] + " round keys:");
                for (int i = 0; i < 16; i++)
                    System.out.println("    Round key " + (i + 1) + ": " + allRK[k][i]);
            }
        }

        // Encrypt every block with Triple DES and concatenate results
        System.out.println("\n--- Encryption ---");
        System.out.println("Original input: " + originalInput);

        StringBuilder cipherBin = new StringBuilder();
        for (int i = 0; i < n; i++) {
            String cBlock = tripleDesEncryptBlock(blocks.get(i), rk1, rk2, rk3);
            cipherBin.append(cBlock);
        }

        System.out.println("\n*** ENCRYPTED MESSAGE ***");
        System.out.println("Binary      : " + cipherBin.substring(0, 64) + (n > 1 ? "..." : ""));
        System.out.println("Hexadecimal : " + binaryToHex(cipherBin.toString()));

        // Optionally show the detailed 48-step verbose trace (3 × 16 rounds)
        System.out.print("\nDo you want to see the encryption process details? (yes/no): ");
        if (isYes(sc.nextLine())) {
            System.out.println("\n--- Detailed Encryption Process (Block 1) ---");
            tripleDesEncryptVerbose(blocks.get(0), rk1, rk2, rk3);
        }

        // Optionally decrypt to verify the round-trip is correct
        System.out.print("\nDo you want to decrypt the message? (yes/no): ");
        if (isYes(sc.nextLine())) {
            System.out.println("\n--- Decryption ---");

            StringBuilder decBin = new StringBuilder();
            for (int i = 0; i < n; i++) {
                String cBlock = cipherBin.substring(i * 64, (i + 1) * 64);
                decBin.append(tripleDesDecryptBlock(cBlock, rk1, rk2, rk3));
            }

            System.out.println("\n*** DECRYPTED MESSAGE ***");
            System.out.println("Binary      : " + decBin.substring(0, 64) + (n > 1 ? "..." : ""));
            if (choice == 1)
                System.out.println("Plaintext   : " + binaryToString(decBin.toString()));
            else
                System.out.println("Hexadecimal : " + binaryToHex(decBin.toString()));

            System.out.print("\nDo you want to see the decryption process details? (yes/no): ");
            if (isYes(sc.nextLine())) {
                System.out.println("\n--- Detailed Decryption Process (Block 1) ---");
                tripleDesDecryptVerbose(cipherBin.substring(0, 64), rk1, rk2, rk3);
            }
        }

        // Persist results so the MITM section can reuse them without re-entering data
        List<String> cipherBlockList = new ArrayList<>();
        for (int i = 0; i < n; i++)
            cipherBlockList.add(cipherBin.substring(i * 64, (i + 1) * 64));
        lastPlainBlocks  = blocks;
        lastCipherBlocks = cipherBlockList;
        lastK1 = k1Str;
        lastK2 = k2Str;
        lastK3 = k3Str;
    }


    // ─────────────────────────────────────────────────────────
    // SECTION 3 — MEET-IN-THE-MIDDLE (MITM) ATTACK
    // ─────────────────────────────────────────────────────────
    //
    // Concept:
    //   In Triple DES:  C = E_K3( D_K2( E_K1( P ) ) )
    //
    //   Introduce a "cut point" between D_K2 and E_K3, calling the intermediate value z:
    //     Forward:  z = D_K2( E_K1(P) )      (computed from the plaintext side)
    //     Backward: z = D_K3( C )             (computed from the ciphertext side)
    //   A correct key triple (K1, K2, K3) will produce the same z from both sides.
    //
    // Attack model used here (simplified for demonstration):
    //   - The attacker KNOWS the last 7 bytes (characters 2–8) of each key.
    //   - The attacker must find the FIRST byte of each key (256 possibilities each).
    //   - This reduces the search from 2^168 to 256×256×256 = 16,777,216 guesses.
    //
    // Two-phase algorithm:
    //
    //   Phase I — Build a lookup table (HashMap):
    //     For every combination of (first byte of K1, first byte of K2):   256 × 256 = 65,536 pairs
    //       z = D_K2( E_K1(plaintext) )
    //       store: HashMap[ z ] → (b1, b2)
    //
    //   Phase II — Search from the ciphertext side:
    //     For every candidate for the first byte of K3:                      256 candidates
    //       z = D_K3( ciphertext )
    //       if z is in HashMap → (K1, K2, K3) is a candidate key triple
    //       verify against a second plaintext/ciphertext pair to eliminate false positives
    //
    // Complexity:
    //   Time:   O(256²) for Phase I  +  O(256) for Phase II  ≪  O(256³) brute force
    //   Space:  O(256²) entries in the HashMap
    //
    // Why does MITM work?
    //   The cut point lets us "meet" the forward and backward computations at the same
    //   intermediate value z, without having to enumerate all 256³ combinations.
    //   This is why Double DES gives only ~57 bits of security instead of 112 bits.
    // ─────────────────────────────────────────────────────────

    /**
     * Part 2 — Interactive Meet-in-the-Middle attack simulation.
     *
     * Uses known plaintext/ciphertext pairs from Part 1 (or prompts the user for new ones).
     * Recovers the unknown first byte of each key using the two-phase MITM algorithm.
     */
    static void runPartTwo(Scanner sc) {
        System.out.println("\nMeet-in-the-Middle (MITM) Attack on Triple DES");
        System.out.println("-----------------------------------------------");
        System.out.println("Model : y = E_K3( D_K2( E_K1(x) ) )  [EDE mode]");
        System.out.println("Known : plaintext x, ciphertext y,");
        System.out.println("         the last 7 bytes (chars 2-8) of K1, K2, and K3.");
        System.out.println("Unknown: first byte of K1, K2, and K3 (8 bits each = 256 possibilities each).");
        System.out.println("Cut pt : between D_K2 and E_K3.");
        System.out.println("Phase I : try all 256x256 (K1,K2) pairs -> build HashMap of z = D_K2(E_K1(x))");
        System.out.println("Phase II: try all 256 K3 guesses -> z = D_K3(y), look up in HashMap.");
        System.out.println("(False positives eliminated by verifying candidates against a second block.)");

        // ── Input setup ────────────────────────────────────────────────────────────
        // Use plaintext/ciphertext/keys from Part 1 if available; otherwise prompt user.
        List<String> plainBlocks, cipherBlocks;
        String k1Base, k2Base, k3Base;

        if (lastPlainBlocks != null) {
            System.out.println("  Total blocks available : " + lastPlainBlocks.size());
            System.out.println("  Block 1 plaintext (hex): " + binaryToHex(lastPlainBlocks.get(0)));
            System.out.println("  K1 known suffix (chars 2-8): \"" + lastK1.substring(1) + "\"");
            System.out.println("  K2 known suffix (chars 2-8): \"" + lastK2.substring(1) + "\"");
            System.out.println("  K3 known suffix (chars 2-8): \"" + lastK3.substring(1) + "\"");
            plainBlocks  = lastPlainBlocks;
            cipherBlocks = lastCipherBlocks;
            k1Base = lastK1;
            k2Base = lastK2;
            k3Base = lastK3;
        } else {
            // No Part 1 data: ask user for plaintext and keys, then simulate encryption
            System.out.println("\nNo Part 1 data found — please enter values manually.");
            System.out.print("Enter plaintext (any size, will be split into 64-bit blocks): ");
            String pt = sc.nextLine();
            String binaryAll = stringToBinary(pt);
            plainBlocks = splitIntoBlocks(binaryAll);
            System.out.println("Binary representation (block 1): " + plainBlocks.get(0));
            System.out.println("Total blocks: " + plainBlocks.size());
            k1Base = readValidKey(sc, "K1 (full key, for simulation)");
            k2Base = readValidKey(sc, "K2 (full key, for simulation)");
            k3Base = readValidKey(sc, "K3 (full key, for simulation)");

            // Simulate encryption so we have a known ciphertext to attack
            String[] rk1f = generateKeys(stringToBinary(k1Base));
            String[] rk2f = generateKeys(stringToBinary(k2Base));
            String[] rk3f = generateKeys(stringToBinary(k3Base));
            cipherBlocks = new ArrayList<>();
            for (String pb : plainBlocks)
                cipherBlocks.add(tripleDesEncryptBlock(pb, rk1f, rk2f, rk3f));
        }

        // We attack only block 1; block 2 (if available) is used to filter false positives
        String plainBlock   = plainBlocks.get(0);
        String tripleCipher = cipherBlocks.get(0);

        System.out.println("\nTriple-DES ciphertext (block 1) y = E_K3(D_K2(E_K1(x))):");
        System.out.println("Binary : " + tripleCipher);
        System.out.println("Hexadecimal : " + binaryToHex(tripleCipher));

        // If two or more blocks exist, we can verify candidates against block 2
        boolean hasVerifyPair = plainBlocks.size() >= 2;
        if (hasVerifyPair) {
            System.out.println("  (Block 2 will be used to eliminate false positives)");
        } else {
            System.out.println("  WARNING: Only 1 plaintext block available.");
            System.out.println("  False positives are possible. For best results provide");
            System.out.println("  a plaintext of more than 8 characters so a 2nd block is available.");
        }

        // The attacker knows bytes 2–8 of each key; only byte 1 (0–255) is unknown
        String k1Suffix = k1Base.substring(1); // known last 7 chars of K1
        String k2Suffix = k2Base.substring(1); // known last 7 chars of K2
        String k3Suffix = k3Base.substring(1); // known last 7 chars of K3

        // ── Phase I: Build the lookup table ────────────────────────────────────────
        //
        // For every possible (first byte of K1, first byte of K2) pair (256 × 256 = 65,536):
        //   1. Build the full K1 guess = (candidate byte) + known K1 suffix
        //   2. Encrypt the plaintext with K1 guess:  afterK1 = E_K1(plaintext)
        //   3. Build the full K2 guess = (candidate byte) + known K2 suffix
        //   4. Decrypt afterK1 with K2 guess:        z = D_K2(E_K1(plaintext))
        //   5. Store z → encoded (b1, b2) pair in the HashMap
        //
        // The HashMap key is the intermediate binary string z;
        // the value encodes the two candidate bytes as a single integer: b1 * 256 + b2.

        System.out.println("\n--- Phase I: Building Lookup Table ---");
        System.out.println("Computing z = D_K2( E_K1(x) ) for all 256x256 = 65,536");
        System.out.println("combinations of (first byte of K1, first byte of K2)...");

        HashMap<String, Integer> table = new HashMap<>(65536);
        int phaseICount = 0;

        for (int b1 = 0; b1 < 256; b1++) {
            // Construct the full K1 guess: unknown byte b1 (as a char) + known suffix
            String k1Guess = (char) b1 + k1Suffix;
            String[] rk1g  = generateKeys(stringToBinary(k1Guess));

            // Compute E_K1(plaintext) once per b1 — reused for all 256 b2 values
            String afterK1 = desCore(plainBlock, rk1g, true);

            for (int b2 = 0; b2 < 256; b2++) {
                String k2Guess = (char) b2 + k2Suffix;
                String[] rk2g  = generateKeys(stringToBinary(k2Guess));

                // Compute z = D_K2( E_K1(x) ) — the intermediate value at the cut point
                String z = desCore(afterK1, rk2g, false);

                // Store first-found (b1, b2) for this z value
                // (putIfAbsent avoids overwriting genuine matches with later collisions)
                table.putIfAbsent(z, b1 * 256 + b2);
                phaseICount++;
            }
        }

        System.out.println("Phase I complete — " + phaseICount + " iterations, "
                + table.size() + " unique intermediate values stored.");

        // ── Phase II: Match from the ciphertext side ────────────────────────────────
        //
        // For every possible first byte of K3 (256 candidates):
        //   1. Build K3 guess = (candidate byte) + known K3 suffix
        //   2. Compute z = D_K3(ciphertext)  — the intermediate value from the right side
        //   3. If z is in the Phase I table → (K1, K2, K3) candidate found
        //   4. Verify against block 2 to eliminate false positives before accepting

        System.out.println("\n--- Phase II: Matching Against Lookup Table ---");
        System.out.println("Computing z = D_K3(y) for all 256 possible values of");
        System.out.println("the unknown first byte of K3, checking for collisions,");
        if (hasVerifyPair)
            System.out.println("and verifying each candidate against block 2...");

        int foundPair = -1, foundK3Byte = -1;
        int phaseIIAttempts = 0, falsePositives = 0;

        for (int b3 = 0; b3 < 256; b3++) {
            phaseIIAttempts++;
            String k3Guess = (char) b3 + k3Suffix;
            String[] rk3g  = generateKeys(stringToBinary(k3Guess));

            // Compute D_K3(ciphertext) — the intermediate value working backward from C
            String z = desCore(tripleCipher, rk3g, false);

            if (table.containsKey(z)) {
                // Collision found: forward and backward z values match
                int candidatePair = table.get(z);
                int cb1 = candidatePair / 256; // recovered first byte of K1
                int cb2 = candidatePair % 256; // recovered first byte of K2

                // Verify against block 2 to rule out false positives
                // (A false positive is a (K1,K2,K3) that accidentally produces the same z
                //  for block 1 but differs for block 2.)
                if (hasVerifyPair) {
                    String ck1 = (char) cb1 + k1Suffix;
                    String ck2 = (char) cb2 + k2Suffix;
                    String ck3 = k3Guess;
                    String[] vrk1 = generateKeys(stringToBinary(ck1));
                    String[] vrk2 = generateKeys(stringToBinary(ck2));
                    String[] vrk3 = generateKeys(stringToBinary(ck3));

                    // Fully encrypt block 2 with the candidate keys
                    String verify = tripleDesEncryptBlock(plainBlocks.get(1), vrk1, vrk2, vrk3);

                    if (!verify.equals(cipherBlocks.get(1))) {
                        falsePositives++; // block 2 doesn't match → discard this candidate
                        continue;
                    }
                }

                // Candidate passed verification → genuine key found
                foundPair   = candidatePair;
                foundK3Byte = b3;
                break; // stop after finding the first valid key triple
            }
        }

        System.out.println("Phase II complete — " + phaseIIAttempts + " K3 candidate(s) tested.");
        if (falsePositives > 0)
            System.out.println("False positives eliminated by block-2 verification: " + falsePositives);

        // ── Results ─────────────────────────────────────────────────────────────────

        System.out.println("\n--- MITM Attack Results ---");
        if (foundPair == -1) {
            System.out.println("No valid collision found after false-positive elimination.");
            System.out.println("Please verify your inputs.");
            return;
        }

        int foundK1Byte = foundPair / 256;
        int foundK2Byte = foundPair % 256;

        // Reconstruct the full recovered keys: recovered first byte + known suffix
        String recoveredK1 = (char) foundK1Byte + k1Suffix;
        String recoveredK2 = (char) foundK2Byte + k2Suffix;
        String recoveredK3 = (char) foundK3Byte + k3Suffix;

        System.out.println("Recovered first byte of K1 : ASCII " + foundK1Byte
                + "  (0x" + String.format("%02X", foundK1Byte) + ")"
                + (foundK1Byte >= 32 ? "  char '" + (char) foundK1Byte + "'" : "  (non-printable)"));
        System.out.println("Recovered first byte of K2 : ASCII " + foundK2Byte
                + "  (0x" + String.format("%02X", foundK2Byte) + ")"
                + (foundK2Byte >= 32 ? "  char '" + (char) foundK2Byte + "'" : "  (non-printable)"));
        System.out.println("Recovered first byte of K3 : ASCII " + foundK3Byte
                + "  (0x" + String.format("%02X", foundK3Byte) + ")"
                + (foundK3Byte >= 32 ? "  char '" + (char) foundK3Byte + "'" : "  (non-printable)"));
        System.out.println("Recovered K1               : " + recoveredK1);
        System.out.println("Recovered K2               : " + recoveredK2);
        System.out.println("Recovered K3               : " + recoveredK3);
        System.out.println("Actual    K1               : " + k1Base);
        System.out.println("Actual    K2               : " + k2Base);
        System.out.println("Actual    K3               : " + k3Base);

        // Final verification: encrypt block 1 with recovered keys and compare to known ciphertext
        String[] vrk1    = generateKeys(stringToBinary(recoveredK1));
        String[] vrk2    = generateKeys(stringToBinary(recoveredK2));
        String[] vrk3    = generateKeys(stringToBinary(recoveredK3));
        String verCipher = tripleDesEncryptBlock(plainBlock, vrk1, vrk2, vrk3);
        boolean ok       = verCipher.equals(tripleCipher);
        System.out.println("\nVerification E_K3(D_K2(E_K1(plain))) == ciphertext : "
                + (ok ? "PASSED" : "FAILED"));

        // Optionally show the full MITM intermediate values for inspection
        System.out.print("\nDo you want to see the MITM process details? (yes/no): ");
        if (isYes(sc.nextLine())) {
            System.out.println("\n--- Detailed MITM Trace ---");

            // Recompute the forward chain step by step
            String step1 = desCore(plainBlock, vrk1, true);  // E_K1(x)
            String step2 = desCore(step1,      vrk2, false); // D_K2(E_K1(x)) = z (forward)
            String step3 = desCore(step2,      vrk3, true);  // E_K3(z) = C (full 3DES)
            String back1 = desCore(tripleCipher, vrk3, false); // D_K3(C) = z (backward)

            System.out.println("Forward chain (Phase I cut point):");
            System.out.println("  x                     (hex) : " + binaryToHex(plainBlock));
            System.out.println("  E_K1(x)               (hex) : " + binaryToHex(step1));
            System.out.println("  D_K2(E_K1(x))  = z    (hex) : " + binaryToHex(step2));
            System.out.println("Backward chain (Phase II cut point):");
            System.out.println("  y                     (hex) : " + binaryToHex(tripleCipher));
            System.out.println("  D_K3(y)        = z    (hex) : " + binaryToHex(back1));
            System.out.println("Collision: z values match      : " + step2.equals(back1));
            System.out.println("Full re-encryption result (hex): " + binaryToHex(step3));
            System.out.println("Expected ciphertext       (hex): " + binaryToHex(tripleCipher));
            System.out.println("Match                          : " + ok);

            if (hasVerifyPair) {
                System.out.println("\nBlock-2 verification:");
                String v2 = tripleDesEncryptBlock(plainBlocks.get(1), vrk1, vrk2, vrk3);
                System.out.println("  Block 2 plain  (hex): " + binaryToHex(plainBlocks.get(1)));
                System.out.println("  Re-encrypt     (hex): " + binaryToHex(v2));
                System.out.println("  Expected       (hex): " + binaryToHex(cipherBlocks.get(1)));
                System.out.println("  Match               : " + v2.equals(cipherBlocks.get(1)));
            }
        }
    }


    // ─────────────────────────────────────────────────────────
    // MAIN — top-level menu
    // ─────────────────────────────────────────────────────────

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        boolean running = true;

        System.out.println("\n=========================================");
        System.out.println("Triple DES and Meet-in-the-Middle Attack");
        System.out.println("=========================================\n");

        while (running) {
            System.out.println("  1. Part 1 — Triple DES Encryption & Decryption");
            System.out.println("  2. Part 2 — MITM Attack on Triple DES");
            System.out.println("  3. Exit");
            System.out.print("Select an option: ");
            String choice = sc.nextLine().trim();

            switch (choice) {
                case "1": runPartOne(sc); break;  // Run Triple DES demo
                case "2": runPartTwo(sc); break;  // Run MITM attack demo
                case "3": running = false; break; // Exit the program
                default:  System.out.println("Invalid option. Please enter 1, 2, or 3."); continue;
            }

            if (running) {
                System.out.print("\nDo you want to input another message and key? (yes/no): ");
                if (!isYes(sc.nextLine())) running = false;
            }
        }

        System.out.println("\nThank you for using the Triple DES Tool!");
        sc.close();
    }
}