/**
 * Linear Feedback Shift Register (LFSR) Key Generator
 * 
 * This application implements a cryptographic key stream generator based on Linear Feedback
 * Shift Register principles. It provides functionality for generating pseudorandom sequences
 * suitable for stream cipher applications.
 * 
 * Features:
 * - Configurable LFSR implementation with customizable seed and tap positions
 * - Support for optimal tap position selection to maximize period length
 * - Key stream validation to ensure cryptographic quality
 * - Built-in encryption and decryption capabilities using XOR operations
 * - Detailed state visualization during key generation process
 */

package javaagain;

import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;

public class LFSRKeyGenerator {
    private int[] register; // Current state of the LFSR
    private int[] taps;     // Selected feedback tap positions
    private int m;          // Length of the register in bits

    /**
     * Constructs a new LFSR with the specified initial state and tap positions.
     * 
     * @param seed Initial binary state of the register
     * @param tapPositions Array of indices representing feedback tap positions
     */
    public LFSRKeyGenerator(String seed, int[] tapPositions) {
        this.m = seed.length();
        this.register = new int[m];
        this.taps = tapPositions;

        // Initialize register with seed values
        for (int i = 0; i < m; i++) {
            register[i] = seed.charAt(i) - '0';
        }
    }

    /**
     * Performs a single clock cycle shift operation on the LFSR.
     * 
     * @return The output bit from this shift operation
     */
    public int shift() {
        int feedback = 0;

        // Calculate feedback bit by XORing all tap positions
        for (int tap : taps) {
            feedback ^= register[tap];
        }

        int output = register[m - 1];

        // Shift register contents
        System.arraycopy(register, 0, register, 1, m - 1);
        register[0] = feedback;

        return output;
    }

    /**
     * Generates a complete key stream sequence until repetition is detected.
     * 
     * @return The generated key stream as a binary string
     */
    public String generateKeyStream() {
        StringBuilder keyStream = new StringBuilder();
        System.out.println("Clock Cycle | Register State | Feedback Bit | Output Bit");
        System.out.println("-------------------------------------------------------");

        Map<String, Integer> seenStates = new HashMap<>();
        int cycle = 0;
        boolean hasOne = false;
        int maxLength = (1 << m) - 1; // Maximum theoretical period (2^m - 1)

        // Generate key stream until state repetition or maximum length reached
        while (cycle < maxLength) {
            String state = Arrays.toString(register);
            if (seenStates.containsKey(state)) break;
            seenStates.put(state, cycle);

            int output = shift();
            keyStream.append(output);
            if (output == 1) {
                hasOne = true;
            }

            System.out.printf("%11d | %s | %d | %d\n", cycle, state, register[0], output);
            cycle++;
        }

        // Validate key stream quality
        if (!hasOne) {
            System.out.println("Error: Key stream consists entirely of zeros. Please verify tap positions and seed values.");
            return "";
        }
        return keyStream.toString();
    }

    /**
     * Identifies optimal tap positions that form a primitive polynomial,
     * ensuring maximum-length sequences for the given register size.
     * 
     * @param m Length of the LFSR register
     * @return Array of optimal tap positions
     */
    public static int[] findPrimitiveTaps(int m) {
        List<int[]> candidates = generateTapCombinations(m);

        for (int[] taps : candidates) {
            if (isPrimitivePolynomial(m, taps)) {
                return taps;
            }
        }

        // Fallback to a simple configuration if no primitive polynomial found
        return new int[]{m - 1, m - 2};
    }

    /**
     * Generates all possible combinations of tap positions for a given register length.
     * 
     * @param m Length of the LFSR register
     * @return List of possible tap position combinations
     */
    private static List<int[]> generateTapCombinations(int m) {
        List<int[]> tapSets = new ArrayList<>();

        for (int i = 1; i < (1 << (m - 1)); i++) {
            List<Integer> taps = new ArrayList<>();
            taps.add(m - 1); // Always include the highest bit position

            // Identify tap positions from binary representation
            for (int j = 0; j < m - 1; j++) {
                if ((i & (1 << j)) != 0) {
                    taps.add(j);
                }
            }
            tapSets.add(taps.stream().mapToInt(Integer::intValue).toArray());
        }

        return tapSets;
    }

    /**
     * Verifies if the given combination of taps forms a primitive polynomial,
     * which produces a maximum-length sequence.
     * 
     * @param m Length of the LFSR register
     * @param taps Array of tap positions to evaluate
     * @return True if the taps form a primitive polynomial
     */
    private static boolean isPrimitivePolynomial(int m, int[] taps) {
        LFSRKeyGenerator testLFSR = new LFSRKeyGenerator("1".repeat(m), taps);
        Set<String> seenStates = new HashSet<>();

        // Test for maximum cycle length (2^m - 1)
        for (int i = 0; i < (1 << m) - 1; i++) {
            String state = Arrays.toString(testLFSR.register);

            if (seenStates.contains(state)) {
                return false;
            }

            seenStates.add(state);
            testLFSR.shift();
        }

        return seenStates.size() == (1 << m) - 1;
    }

    /**
     * Encrypts text using XOR with the key stream.
     * 
     * @param plaintext Text to encrypt
     * @param keyStream Key stream to use for encryption
     * @return Encrypted text
     */
    public static String encrypt(String plaintext, String keyStream) {
        if (keyStream.isEmpty()) {
            return "[Error: Invalid Key Stream]";
        }

        StringBuilder ciphertext = new StringBuilder();

        for (int i = 0; i < plaintext.length(); i++) {
            char encryptedChar = (char) (plaintext.charAt(i) ^ keyStream.charAt(i % keyStream.length()));
            ciphertext.append(encryptedChar);
        }
        return ciphertext.toString();
    }

    /**
     * Decrypts ciphertext using XOR with the key stream.
     * 
     * @param ciphertext Text to decrypt
     * @param keyStream Key stream to use for decryption
     * @return Decrypted text
     */
    public static String decrypt(String ciphertext, String keyStream) {
        return encrypt(ciphertext, keyStream); // XOR is symmetric for encryption/decryption
    }

    /**
     * Encrypts binary data using XOR with the key stream.
     * 
     * @param binaryPlaintext Binary string (consisting of 0s and 1s) to encrypt
     * @param keyStream Key stream to use for encryption
     * @return Encrypted binary string
     */
    public static String encryptBinary(String binaryPlaintext, String keyStream) {
        if (keyStream.isEmpty()) {
            return "[Error: Invalid Key Stream]";
        }
        if (!binaryPlaintext.matches("[01]+")) {
            return "[Error: Binary plaintext must contain only 0s and 1s]";
        }

        StringBuilder binaryCiphertext = new StringBuilder();

        for (int i = 0; i < binaryPlaintext.length(); i++) {
            char encryptedBit = (char) ((binaryPlaintext.charAt(i) ^ keyStream.charAt(i % keyStream.length())) + '0');
            binaryCiphertext.append(encryptedBit);
        }
        return binaryCiphertext.toString();
    }

    /**
     * Decrypts binary ciphertext using XOR with the key stream.
     * 
     * @param binaryCiphertext Binary string to decrypt
     * @param keyStream Key stream to use for decryption
     * @return Decrypted binary string
     */
    public static String decryptBinary(String binaryCiphertext, String keyStream) {
        return encryptBinary(binaryCiphertext, keyStream); // XOR is symmetric for encryption/decryption
    }

    /**
     * Main application entry point.
     * 
     * @param args Command line arguments (not used)
     */
    public static void main(String[] args) {
        System.out.println("==============================================\n"
                + "             LFSR Key Generator \n"
                + "==============================================\n"
                + "This program generates a secure key stream\n"
                + "using a Linear Feedback Shift Register (LFSR),\n"
                + "a core component in stream cipher encryption.\n\n"
                + "Start by entering your seed below!\n"
                + "-----------------------------------------------\n");

        Scanner scanner = new Scanner(System.in);
        String keyStream = "";

        // Main application loop
        while (true) {
            String seed;
            do {
                System.out.print("Enter seed (binary, at least 7 bits, must contain at least one '1'): ");
                seed = scanner.next();
                // Validate seed requirements
                if (seed.length() < 7 || !seed.matches("[01]+") || !seed.contains("1")) {
                    System.out.println("Invalid seed! Enter at least 7 bits containing at least one '1'.");
                }
            } while (seed.length() < 7 || !seed.matches("[01]+") || !seed.contains("1"));

            int m = seed.length();
            int[] taps;

            // Tap selection loop
            while (true) {
                System.out.print("Do you want to manually choose taps? (yes/no): ");
                String choice = scanner.next().toLowerCase();
                System.out.println("Recommended taps: " + Arrays.toString(findPrimitiveTaps(m)));

                if (choice.equals("yes")) {
                    System.out.print("Enter number of taps: ");
                    int numTaps = scanner.nextInt();
                    taps = new int[numTaps];
                    System.out.println("Enter tap positions (0-based index, must be less than " + m + "):");
                    for (int i = 0; i < numTaps; i++) {
                        int tap;
                        do {
                            tap = scanner.nextInt();
                            // Validate tap position boundaries
                            if (tap >= m || tap < 0) {
                                System.out.println("Invalid tap position! Must be between 0 and " + (m - 1) + ". Try another tap position:");
                            }
                        } while (tap >= m || tap < 0);
                        taps[i] = tap;
                    }
                } else {
                    taps = findPrimitiveTaps(m);
                    System.out.println("Using optimal taps: " + Arrays.toString(taps));
                }

                LFSRKeyGenerator lfsr = new LFSRKeyGenerator(seed, taps);
                keyStream = lfsr.generateKeyStream();

                // Key quality verification
                if (keyStream.length() < 100) {
                    System.out.println("Warning: Key stream is less than 100 bits.");
                    System.out.print("(1) Choose new taps\n(2) Show key anyway (1/2):");
                    int decision = scanner.nextInt();
                    if (decision == 1) continue;
                }
                break;
            }

            // Display key stream in formatted chunks
            System.out.println("Generated Key Stream: ");
            for (int i = 0; i < keyStream.length(); i += 50) {
                System.out.println(keyStream.substring(i, Math.min(i + 50, keyStream.length())));
            }

            // Encryption/decryption loop
            while (true) {
                System.out.print("Do you want to encrypt \n1-Text \n2-Binary Data? (1/2): ");
                int encryptionType = scanner.nextInt();
                scanner.nextLine(); // Clear input buffer

                if (encryptionType == 1) {
                    System.out.print("Enter plaintext message: ");
                    String plaintext = scanner.nextLine();
                    String encryptedText = encrypt(plaintext, keyStream);
                    System.out.println("Encrypted: " + encryptedText);
                    System.out.println("Decrypted: " + decrypt(encryptedText, keyStream));
                } else if (encryptionType == 2) {
                    System.out.print("Enter binary plaintext (0s and 1s): ");
                    String binaryPlaintext = scanner.nextLine();

                    String encryptedBinary = encryptBinary(binaryPlaintext, keyStream);
                    System.out.println("Encrypted Binary: " + encryptedBinary);
                    System.out.println("Decrypted Binary: " + decryptBinary(encryptedBinary, keyStream));
                } else {
                    System.out.println("Invalid choice! Try again.");
                }

                System.out.print("Do you want to encrypt another message? (yes/no): ");
                if (!scanner.next().equalsIgnoreCase("yes")) break;
            }

            System.out.print("Do you want to generate another key? (yes/no): ");
            if (!scanner.next().equalsIgnoreCase("yes")) break;
        }
        scanner.close();
    }
}