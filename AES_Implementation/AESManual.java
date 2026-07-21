package AESManual;

import java.util.Scanner;
import java.util.Arrays;
import java.util.Random;

/**
 * AESManual - A manual implementation of the Advanced Encryption Standard (AES) algorithm
 * This class provides methods for encrypting and decrypting data using the AES algorithm,
 * supporting AES-128, AES-192, and AES-256 variants.
 */
public class AESManual {
    
    // S-Box lookup table for SubBytes transformation
    private static final int[] SBOX = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };
    
    // Inverse S-Box lookup table for InvSubBytes transformation
    private static final int[] INV_SBOX = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };
    
    // Round constants used in key expansion
    private static final int[] RCON = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A
    };
    
    // Block size in bytes (always 16 bytes/128 bits for AES)
    private static final int BLOCK_SIZE = 16;
    
    /**
     * Main method - provides interactive console interface for AES encryption/decryption
     */
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        boolean continueProgram = true;
        
        while (continueProgram) {
            System.out.println("\nAES Encryption and Decryption Implementation");
            System.out.println("-------------------------------------------");
            
            // Get input format preference from user
            System.out.print("Do you want to enter (1) Plaintext (ASCII), (2) Binary, or (3) Hexadecimal? ");
            int inputFormat = sc.nextInt();
            sc.nextLine(); // Consume newline
            
            // Get user input based on chosen format
            System.out.print("Enter your message (will be truncated to 128 bits/16 bytes if needed): ");
            String userInput = sc.nextLine();
            
            // Convert to binary based on input format and ensure 128 bits
            String binaryPlaintext = "";
            String originalInput = userInput;
            
            switch (inputFormat) {
                case 1: // ASCII
                    if (userInput.length() > 16) {
                        userInput = userInput.substring(0, 16);
                        System.out.println("Input truncated to 16 bytes: " + userInput);
                    } else if (userInput.length() < 16) {
                        userInput = String.format("%-16s", userInput); // Pad with spaces
                    }
                    originalInput = userInput;
                    binaryPlaintext = stringToBinary(userInput);
                    break;
                    
                case 2: // Binary
                    binaryPlaintext = userInput.replaceAll("[^01]", ""); // Remove non-binary characters
                    if (binaryPlaintext.length() > 128) {
                        binaryPlaintext = binaryPlaintext.substring(0, 128);
                        System.out.println("Binary input truncated to 128 bits");
                    } else if (binaryPlaintext.length() < 128) {
                        // Pad with zeros
                        binaryPlaintext = String.format("%-128s", binaryPlaintext).replace(' ', '0');
                    }
                    break;
                    
                case 3: // Hexadecimal
                    userInput = userInput.replaceAll("[^0-9A-Fa-f]", ""); // Remove non-hex characters
                    if (userInput.length() > 32) {
                        userInput = userInput.substring(0, 32);
                        System.out.println("Hex input truncated to 32 digits (128 bits): " + userInput);
                    } else if (userInput.length() < 32) {
                        // Pad with zeros
                        userInput = String.format("%-32s", userInput).replace(' ', '0');
                    }
                    binaryPlaintext = hexToBinary(userInput);
                    break;
                    
                default:
                    System.out.println("Invalid choice. Using ASCII format.");
                    if (userInput.length() > 16) {
                        userInput = userInput.substring(0, 16);
                        System.out.println("Input truncated to 16 bytes: " + userInput);
                    }
                    originalInput = userInput;
                    binaryPlaintext = stringToBinary(userInput);
            }
            
            System.out.println("Binary representation (128 bits): " + binaryPlaintext);
            
            // Select AES variant (key length)
            System.out.println("\nChoose AES variant:");
            System.out.println("1) AES-128 (128-bit key, 10 rounds)");
            System.out.println("2) AES-192 (192-bit key, 12 rounds)");
            System.out.println("3) AES-256 (256-bit key, 14 rounds)");
            System.out.print("Your choice: ");
            int aesVariant = sc.nextInt();
            sc.nextLine(); // Consume newline
            
            int keySize = 128; // Default size in bits
            int rounds = 10;   // Default rounds
            
            switch (aesVariant) {
                case 2:
                    keySize = 192;
                    rounds = 12;
                    break;
                case 3:
                    keySize = 256;
                    rounds = 14;
                    break;
                default:
                    keySize = 128;
                    rounds = 10;
            }
            
            System.out.println("Using AES-" + keySize + " with " + rounds + " rounds");
            
            // Get key from user or generate one
            String binaryKey;
            String keyHex = "";
            
            System.out.print("Enter key manually? (yes/no): ");
            String keyChoice = sc.nextLine().toLowerCase();
            
            if (keyChoice.equals("yes") || keyChoice.equals("y")) {
                System.out.println("Enter key in the same format as input (will be padded/truncated to " + keySize + " bits):");
                String userKey = sc.nextLine();
                
                // Process key based on input format
                switch (inputFormat) {
                    case 1: // ASCII
                        int keySizeBytes = keySize / 8;
                        if (userKey.length() > keySizeBytes) {
                            userKey = userKey.substring(0, keySizeBytes);
                            System.out.println("Key truncated to " + keySizeBytes + " bytes");
                        } else if (userKey.length() < keySizeBytes) {
                            userKey = String.format("%-" + keySizeBytes + "s", userKey); // Pad with spaces
                        }
                        binaryKey = stringToBinary(userKey);
                        keyHex = binaryToHex(binaryKey);
                        break;
                        
                    case 2: // Binary
                        binaryKey = userKey.replaceAll("[^01]", ""); // Remove non-binary characters
                        if (binaryKey.length() > keySize) {
                            binaryKey = binaryKey.substring(0, keySize);
                            System.out.println("Key truncated to " + keySize + " bits");
                        } else if (binaryKey.length() < keySize) {
                            // Pad with zeros
                            binaryKey = String.format("%-" + keySize + "s", binaryKey).replace(' ', '0');
                        }
                        keyHex = binaryToHex(binaryKey);
                        break;
                        
                    case 3: // Hexadecimal
                        userKey = userKey.replaceAll("[^0-9A-Fa-f]", ""); // Remove non-hex characters
                        int keySizeHex = keySize / 4;
                        if (userKey.length() > keySizeHex) {
                            userKey = userKey.substring(0, keySizeHex);
                            System.out.println("Key truncated to " + keySizeHex + " hex digits");
                        } else if (userKey.length() < keySizeHex) {
                            // Pad with zeros
                            userKey = String.format("%-" + keySizeHex + "s", userKey).replace(' ', '0');
                        }
                        binaryKey = hexToBinary(userKey);
                        keyHex = userKey.toUpperCase();
                        break;
                        
                    default:
                        // Generate random key if something went wrong
                        System.out.println("Invalid format. Generating random key.");
                        keyHex = generateRandomHexKey(keySize);
                        binaryKey = hexToBinary(keyHex);
                }
            } else {
                // Generate random key
                keyHex = generateRandomHexKey(keySize);
                binaryKey = hexToBinary(keyHex);
                System.out.println("Generated random key: " + keyHex);
            }
            
            System.out.println("Key (hex): " + keyHex);
            System.out.println("Key (binary): " + binaryKey);
            
            // Convert binary to state array
            byte[][] state = binaryToState(binaryPlaintext);
            
            // Key expansion
            byte[][] expandedKey = expandKey(hexStringToByteArray(keyHex), rounds);
            
            // Encrypt the plaintext
            String encryptedBinary = "";
            String encryptedHex = "";
            
            // For clean output
            byte[][] encryptedState = encrypt(state, expandedKey, rounds, false);
            encryptedBinary = stateToBinary(encryptedState);
            encryptedHex = binaryToHex(encryptedBinary);
            
            System.out.println("\n*** ENCRYPTED MESSAGE ***");
            System.out.println("Binary: " + encryptedBinary);
            System.out.println("Hexadecimal: " + encryptedHex);
            
            // Ask if the user wants to see the encryption process
            System.out.print("\nDo you want to see the encryption process? (yes/no): ");
            String showEncProcess = sc.nextLine().toLowerCase();
            
            if (showEncProcess.equals("yes") || showEncProcess.equals("y")) {
                System.out.println("\n--- Detailed Encryption Process ---");
                // Re-encrypt with verbose output
                encrypt(binaryToState(binaryPlaintext), expandedKey, rounds, true);
            }
            
            // Ask if the user wants to decrypt the encrypted message
            System.out.print("\nDo you want to decrypt the encrypted message? (yes/no): ");
            String performDecryption = sc.nextLine().toLowerCase();
            
            if (performDecryption.equals("yes") || performDecryption.equals("y")) {
                System.out.println("\n--- Decryption ---");
                
                // Decrypt without showing process
                byte[][] decryptedState = decrypt(encryptedState, expandedKey, rounds, false);
                String decryptedBinary = stateToBinary(decryptedState);
                
                System.out.println("*** DECRYPTED MESSAGE ***");
                System.out.println("Binary: " + decryptedBinary);
                
                // Display in original format
                switch (inputFormat) {
                    case 1:
                        System.out.println("ASCII: " + binaryToString(decryptedBinary));
                        break;
                    case 3:
                        System.out.println("Hexadecimal: " + binaryToHex(decryptedBinary));
                        break;
                }
                
                // Ask if the user wants to see the decryption process
                System.out.print("\nDo you want to see the decryption process? (yes/no): ");
                String showDecProcess = sc.nextLine().toLowerCase();
                
                if (showDecProcess.equals("yes") || showDecProcess.equals("y")) {
                    System.out.println("\n--- Detailed Decryption Process ---");
                    // Re-decrypt with verbose output
                    decrypt(encryptedState, expandedKey, rounds, true);
                }
            }
            
            // Ask if the user wants to encrypt another message
            System.out.print("\nDo you want to encrypt another message? (yes/no): ");
            String continueChoice = sc.nextLine().toLowerCase();
            continueProgram = (continueChoice.equals("yes") || continueChoice.equals("y"));
        }
        
        System.out.println("\nExiting program. Thank you for using the AES encryption tool!");
        sc.close();
    }
    
    /**
     * Generates a random hex key of specified bit length
     * 
     * @param keySize Size of key in bits
     * @return Random key as hex string
     */
    private static String generateRandomHexKey(int keySize) {
        Random rand = new Random();
        StringBuilder keyBuilder = new StringBuilder();
        int hexDigits = keySize / 4;
        
        for (int i = 0; i < hexDigits; i++) {
            int digit = rand.nextInt(16);
            keyBuilder.append(Integer.toHexString(digit).toUpperCase());
        }
        
        return keyBuilder.toString();
    }
    
    /**
     * Converts string to binary
     * 
     * @param input String to convert
     * @return Binary representation as string of 0s and 1s
     */
    public static String stringToBinary(String input) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            result.append(String.format("%8s", Integer.toBinaryString(c)).replace(' ', '0'));
        }
        return result.toString();
    }
    
    /**
     * Converts binary to string
     * 
     * @param binary Binary string to convert
     * @return ASCII string
     */
    public static String binaryToString(String binary) {
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < binary.length(); i += 8) {
            String byteStr = binary.substring(i, Math.min(i + 8, binary.length()));
            // Ensure 8 bits by padding if necessary
            if (byteStr.length() < 8) {
                byteStr = String.format("%-8s", byteStr).replace(' ', '0');
            }
            int charCode = Integer.parseInt(byteStr, 2);
            text.append((char) charCode);
        }
        return text.toString();
    }
    
    /**
     * Converts hexadecimal to binary
     * 
     * @param hex Hexadecimal string
     * @return Binary string
     */
    public static String hexToBinary(String hex) {
        StringBuilder binary = new StringBuilder();
        for (int i = 0; i < hex.length(); i++) {
            int decimal = Integer.parseInt(Character.toString(hex.charAt(i)), 16);
            binary.append(String.format("%4s", Integer.toBinaryString(decimal)).replace(' ', '0'));
        }
        return binary.toString();
    }
    
    /**
     * Converts binary to hexadecimal
     * 
     * @param binary Binary string
     * @return Hexadecimal string
     */
    public static String binaryToHex(String binary) {
        StringBuilder hex = new StringBuilder();
        // Ensure binary length is a multiple of 4
        int padding = binary.length() % 4;
        if (padding != 0) {
            binary = "0".repeat(4 - padding) + binary;
        }
        
        for (int i = 0; i < binary.length(); i += 4) {
            String chunk = binary.substring(i, i + 4);
            int decimal = Integer.parseInt(chunk, 2);
            hex.append(Integer.toHexString(decimal).toUpperCase());
        }
        return hex.toString();
    }
    
    /**
     * Converts binary string to AES state array (4x4 bytes)
     * 
     * @param binary 128-bit binary string
     * @return 4x4 state array
     */
    public static byte[][] binaryToState(String binary) {
        byte[][] state = new byte[4][4];
        for (int i = 0; i < 16; i++) {
            // AES state is column-major order
            int row = i % 4;
            int col = i / 4;
            
            // Extract 8 bits for each byte
            int byteStart = i * 8;
            String byteBinary = binary.substring(byteStart, byteStart + 8);
            byte value = (byte) Integer.parseInt(byteBinary, 2);
            state[row][col] = value;
        }
        return state;
    }
    
    /**
     * Converts AES state array (4x4 bytes) to binary string
     * 
     * @param state 4x4 state array
     * @return 128-bit binary string
     */
    public static String stateToBinary(byte[][] state) {
        StringBuilder binary = new StringBuilder();
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                // Get 8-bit binary representation of each byte
                String byteBinary = String.format("%8s", Integer.toBinaryString(state[row][col] & 0xFF)).replace(' ', '0');
                binary.append(byteBinary);
            }
        }
        return binary.toString();
    }
    
    /**
     * Converts hex string to byte array
     * 
     * @param hex Hexadecimal string
     * @return Byte array
     */
    public static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
    
    /**
     * Print the state array in a readable format
     * 
     * @param state The state array to print
     * @param label A descriptive label for the output
     */
    private static void printState(byte[][] state, String label) {
        System.out.println(label + ":");
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                System.out.printf("%02X ", state[row][col] & 0xFF);
            }
            System.out.println();
        }
        System.out.println();
    }
    
    /**
     * Expands the cipher key into the key schedule
     * 
     * @param key The original cipher key
     * @param rounds Number of rounds for this AES variant
     * @return The expanded key schedule as a byte array
     */
    public static byte[][] expandKey(byte[] key, int rounds) {
        int keyLen = key.length;
        int Nk = keyLen / 4;  // Number of 32-bit words in the key
        int Nr = rounds;      // Number of rounds
        int Nb = 4;           // Number of columns in state (fixed in AES)
        
        byte[][] w = new byte[4 * (Nr + 1)][4]; // Key schedule array
        
        // Copy the input key to the first few words of the key schedule
        for (int i = 0; i < Nk; i++) {
            for (int j = 0; j < 4; j++) {
                w[i][j] = key[4 * i + j];
            }
        }
        
        for (int i = Nk; i < 4 * (Nr + 1); i++) {
            byte[] temp = new byte[4];
            System.arraycopy(w[i - 1], 0, temp, 0, 4);
            
            // Apply core key schedule transformations
            if (i % Nk == 0) {
                // RotWord: rotate the 4 bytes in a word to the left
                byte tempByte = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = tempByte;
                
                // SubWord: apply S-box to each byte
                for (int j = 0; j < 4; j++) {
                    temp[j] = (byte) SBOX[temp[j] & 0xFF];
                }
                
                // XOR with round constant Rcon[i/Nk]
                temp[0] ^= RCON[i / Nk - 1];
            } 
            // For AES-256, if index i-4 is a multiple of Nk, apply SubWord
            else if (Nk > 6 && i % Nk == 4) {
                // SubWord
                for (int j = 0; j < 4; j++) {
                    temp[j] = (byte) SBOX[temp[j] & 0xFF];
                }
            }
            
            // XOR with word Nk positions earlier
            for (int j = 0; j < 4; j++) {
                w[i][j] = (byte) (w[i - Nk][j] ^ temp[j]);
            }
        }
        
        return w;
    }
    
    /**
     * Encrypts the plaintext block using AES
     * 
     * @param state The input state array
     * @param expandedKey The expanded key schedule
     * @param rounds Number of rounds for this AES variant
     * @param verbose If true, print state after each operation
     * @return The encrypted state array
     */
    public static byte[][] encrypt(byte[][] state, byte[][] expandedKey, int rounds, boolean verbose) {
        if (verbose) {
            printState(state, "Initial state");
        }
        
        // Initial round key addition
        addRoundKey(state, expandedKey, 0);
        
        if (verbose) {
            printState(state, "After initial AddRoundKey");
        }
        
        // Main rounds
        for (int round = 1; round < rounds; round++) {
            subBytes(state);
            if (verbose) {
                printState(state, "Round " + round + " after SubBytes");
            }
            
            shiftRows(state);
            if (verbose) {
                printState(state, "Round " + round + " after ShiftRows");
            }
            
            mixColumns(state);
            if (verbose) {
                printState(state, "Round " + round + " after MixColumns");
            }
            
            addRoundKey(state, expandedKey, round);
            if (verbose) {
                printState(state, "Round " + round + " after AddRoundKey");
            }
        }
        
        // Final round (no MixColumns)
        subBytes(state);
        if (verbose) {
            printState(state, "Final round after SubBytes");
        }
        
        shiftRows(state);
        if (verbose) {
            printState(state, "Final round after ShiftRows");
        }
        
        addRoundKey(state, expandedKey, rounds);
        if (verbose) {
            printState(state, "Final round after AddRoundKey (ciphertext)");
        }
        
        return state;
    }
    
    /**
     * Decrypts the ciphertext block using AES
     * 
     * @param state The input state array (ciphertext)
     * @param expandedKey The expanded key schedule
     * @param rounds Number of rounds for this AES variant
     * @param verbose If true, print state after each operation
     * @return The decrypted state array (plaintext)
     */
    public static byte[][] decrypt(byte[][] state, byte[][] expandedKey, int rounds, boolean verbose) {
        if (verbose) {
            printState(state, "Initial state (ciphertext)");
        }
        
        // Initial round key addition
        addRoundKey(state, expandedKey, rounds);
        
        if (verbose) {
            printState(state, "After initial AddRoundKey");
        }
        
        // Main rounds (in reverse)
        for (int round = rounds - 1; round > 0; round--) {
            invShiftRows(state);
            if (verbose) {
                printState(state, "Round " + (rounds - round) + " after InvShiftRows");
            }
            
            invSubBytes(state);
            if (verbose) {
                printState(state, "Round " + (rounds - round) + " after InvSubBytes");
            }
            
            addRoundKey(state, expandedKey, round);
            if (verbose) {
                printState(state, "Round " + (rounds - round) + " after AddRoundKey");
            }
            
            invMixColumns(state);
            if (verbose) {
                printState(state, "Round " + (rounds - round) + " after InvMixColumns");
            }
        }
        
        // Final round (no InvMixColumns)
        invShiftRows(state);
        if (verbose) {
            printState(state, "Final round after InvShiftRows");
        }
        
        invSubBytes(state);
        if (verbose) {
            printState(state, "Final round after InvSubBytes");
        }
        
        addRoundKey(state, expandedKey, 0);
        if (verbose) {
            printState(state, "Final round after AddRoundKey (plaintext)");
        }
        
        return state;
    }
    
    /**
     * SubBytes transformation - substitutes each byte in the state with its corresponding S-box value
     */
    private static void subBytes(byte[][] state) {
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                state[row][col] = (byte) SBOX[state[row][col] & 0xFF];
            }
        }
    }
    
    /**
     * InvSubBytes transformation - substitutes each byte in the state with its corresponding inverse S-box value
     */
    private static void invSubBytes(byte[][] state) {
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                state[row][col] = (byte) INV_SBOX[state[row][col] & 0xFF];
            }
        }
    }
    
    /**
     * ShiftRows transformation - cyclically shifts the last three rows of the state
     */
    private static void shiftRows(byte[][] state) {
        // Row 0: No shift
        
        // Row 1: Shift left by 1
        byte temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;
        
        // Row 2: Shift left by 2
        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;
        
        // Row 3: Shift left by 3 (or right by 1)
        temp = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = temp;
    }
    
    /**
     * InvShiftRows transformation - inverse of ShiftRows
     */
    private static void invShiftRows(byte[][] state) {
        // Row 0: No shift
        
        // Row 1: Shift right by 1
        byte temp = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = temp;
        
        // Row 2: Shift right by 2
        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;
        
        // Row 3: Shift right by 3 (or left by 1)
        temp = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = temp;
    }
    
    /**
     * Galois Field multiplication of two bytes in GF(2^8)
     */
    private static byte gmul(byte a, byte b) {
        byte p = 0;
        byte high_bit;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) == 1) {
                p ^= a;
            }
            high_bit = (byte) (a & 0x80);
            a <<= 1;
            if (high_bit == (byte) 0x80) {
                a ^= 0x1b; // Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11b)
            }
            b >>= 1;
        }
        return p;
    }
    
    /**
     * MixColumns transformation - mixes the columns of the state
     */
    private static void mixColumns(byte[][] state) {
        byte[][] temp = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            System.arraycopy(state[i], 0, temp[i], 0, 4);
        }
        
        for (int col = 0; col < 4; col++) {
            state[0][col] = (byte) (gmul((byte) 0x02, temp[0][col]) ^ 
                                    gmul((byte) 0x03, temp[1][col]) ^ 
                                    temp[2][col] ^ 
                                    temp[3][col]);
                                    
            state[1][col] = (byte) (temp[0][col] ^ 
                                    gmul((byte) 0x02, temp[1][col]) ^
                                    gmul((byte) 0x03, temp[2][col]) ^ 
                                    temp[3][col]);
                                    
            state[2][col] = (byte) (temp[0][col] ^ 
                                    temp[1][col] ^ 
                                    gmul((byte) 0x02, temp[2][col]) ^
                                    gmul((byte) 0x03, temp[3][col]));
                                    
            state[3][col] = (byte) (gmul((byte) 0x03, temp[0][col]) ^ 
                                    temp[1][col] ^ 
                                    temp[2][col] ^ 
                                    gmul((byte) 0x02, temp[3][col]));
        }
    }
    
    /**
     * InvMixColumns transformation - inverse of MixColumns
     */
    private static void invMixColumns(byte[][] state) {
        byte[][] temp = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            System.arraycopy(state[i], 0, temp[i], 0, 4);
        }
        
        for (int col = 0; col < 4; col++) {
            state[0][col] = (byte) (gmul((byte) 0x0e, temp[0][col]) ^ 
                                    gmul((byte) 0x0b, temp[1][col]) ^ 
                                    gmul((byte) 0x0d, temp[2][col]) ^ 
                                    gmul((byte) 0x09, temp[3][col]));
                                    
            state[1][col] = (byte) (gmul((byte) 0x09, temp[0][col]) ^ 
                                    gmul((byte) 0x0e, temp[1][col]) ^
                                    gmul((byte) 0x0b, temp[2][col]) ^ 
                                    gmul((byte) 0x0d, temp[3][col]));
                                    
            state[2][col] = (byte) (gmul((byte) 0x0d, temp[0][col]) ^ 
                                    gmul((byte) 0x09, temp[1][col]) ^ 
                                    gmul((byte) 0x0e, temp[2][col]) ^
                                    gmul((byte) 0x0b, temp[3][col]));
                                    
            state[3][col] = (byte) (gmul((byte) 0x0b, temp[0][col]) ^ 
                                    gmul((byte) 0x0d, temp[1][col]) ^ 
                                    gmul((byte) 0x09, temp[2][col]) ^ 
                                    gmul((byte) 0x0e, temp[3][col]));
        }
    }
    
    /**
     * AddRoundKey transformation - XORs each byte of the state with the round key
     */
    private static void addRoundKey(byte[][] state, byte[][] expandedKey, int round) {
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                state[row][col] ^= expandedKey[round * 4 + col][row];
            }
        }
    }
}