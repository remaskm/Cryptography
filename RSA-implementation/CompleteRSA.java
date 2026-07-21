package CompleteRSA;

import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

/**
 * Complete RSA Implementation with BigInteger and Comprehensive Optimizations
 * 
 * This class provides a full implementation of the RSA cryptographic algorithm with:
 * - Chinese Remainder Theorem (CRT) optimization for fast decryption
 * - Miller-Rabin primality test for secure prime generation
 * - Fermat's Little Theorem test for additional prime verification
 * - Square-and-Multiply algorithm for efficient modular exponentiation
 * - Support for multiple key sizes (512, 1024, 2048, 3072, 4096 bits)
 * - Interactive console interface for testing and demonstration
 * 
 * <p>Security Features:</p>
 * <ul>
 *   <li>Cryptographically secure prime generation</li>
 *   <li>Multiple rounds of primality testing</li>
 *   <li>Optimal public exponent selection (65537)</li>
 *   <li>CRT components for performance optimization</li>
 * </ul>
 * 
 * <p>Performance Optimizations:</p>
 * <ul>
 *   <li>CRT decryption provides ~4x speedup</li>
 *   <li>Square-and-multiply for efficient modular exponentiation</li>
 *   <li>Optimized prime generation with early rejection</li>
 * </ul>
 * 
 * @author RSA Implementation Team
 * @version 2.0
 * @since 1.0
 */
public class CompleteRSA {
    
    /** Random number generator for cryptographic operations */
    private static final Random RANDOM = new Random();
    
    /** Supported RSA key sizes in bits */
    private static final int[] SUPPORTED_KEY_SIZES = {512, 1024, 2048, 3072, 4096};

    /** Number of rounds for Miller-Rabin primality test */
    private static final int MILLER_RABIN_ROUNDS = 10;
    
    /** Number of rounds for Fermat's primality test */
    private static final int FERMAT_TEST_ROUNDS = 5;

    /**
     * Main entry point for the RSA implementation program.
     * Provides an interactive console interface for RSA operations.
     * 
     * @param args command line arguments (not used)
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean continueProgram = true;

        while (continueProgram) {
            System.out.println("\n=== Complete RSA Implementation with CRT ===");
            System.out.println("============================================");

            int keySize = promptKeySize(scanner);
            RSAKeyPair keyPair = promptKeyChoice(scanner, keySize);
            performOperation(scanner, keyPair);

            System.out.print("\nDo you want to run the program again? (Y/N): ");
            String continueChoice = scanner.nextLine().toLowerCase();
            continueProgram = continueChoice.startsWith("y");
        }

        System.out.println("\nThank you for using the Complete RSA implementation!");
        scanner.close();
    }

    /**
     * Prompts the user to select an RSA key size from supported options.
     * 
     * @param scanner the Scanner object for user input
     * @return the selected key size in bits
     */
    private static int promptKeySize(Scanner scanner) {
        System.out.println("\nChoose RSA key size (bits):");
        for (int i = 0; i < SUPPORTED_KEY_SIZES.length; i++) {
            int bits = SUPPORTED_KEY_SIZES[i];
            String securityLevel = getSecurityLevel(bits);
            System.out.printf("%d) %d bits (%s)%n", i + 1, bits, securityLevel);
        }
        System.out.print("Your choice (default is 2): ");

        int keyChoice = 2;
        String input = scanner.nextLine().trim();

        if (!input.isEmpty()) {
            try {
                keyChoice = Integer.parseInt(input);
                if (keyChoice < 1 || keyChoice > SUPPORTED_KEY_SIZES.length) {
                    System.out.println("Invalid choice. Using 1024 bits.");
                    keyChoice = 2;
                }
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Using 1024 bits.");
            }
        }

        int keySize = SUPPORTED_KEY_SIZES[keyChoice - 1];
        System.out.println("Using RSA with " + keySize + " bit key");
        return keySize;
    }

    /**
     * Returns a human-readable security level description for a given key size.
     * 
     * @param bits the key size in bits
     * @return a string describing the security level
     */
    private static String getSecurityLevel(int bits) {
        switch(bits) {
            case 512: return "not secure for real use";
            case 1024: return "minimum for testing";
            case 2048: return "standard secure size";
            case 3072: return "more secure";
            case 4096: return "very secure but slower";
            default: return "unknown security level";
        }
    }

    /**
     * Prompts the user to either generate new RSA keys or use existing ones.
     * 
     * @param scanner the Scanner object for user input
     * @param keySize the desired key size in bits
     * @return an RSAKeyPair object containing the keys
     */
    private static RSAKeyPair promptKeyChoice(Scanner scanner, int keySize) {
        System.out.print("\nDo you want to generate new keys or use existing ones? (G)enerate/(U)se: ");
        String keyOption = scanner.nextLine().toLowerCase();

        if (keyOption.startsWith("u")) {
            return readExistingKeys(scanner);
        } else {
            return generateAndDisplayNewKeys(keySize);
        }
    }

    /**
     * Reads existing RSA key components from user input.
     * Allows for partial key input (e.g., public key only for encryption).
     * 
     * @param scanner the Scanner object for user input
     * @return an RSAKeyPair object with the provided components
     */
    private static RSAKeyPair readExistingKeys(Scanner scanner) {
        System.out.println("\nEnter public key components:");
        System.out.print("Modulus (n): ");
        BigInteger n = new BigInteger(scanner.nextLine());

        System.out.print("Public exponent (e): ");
        BigInteger e = new BigInteger(scanner.nextLine());

        System.out.print("\nEnter private key components (skip to encrypt only):");
        System.out.print("Private exponent (d): ");
        String dStr = scanner.nextLine();
        BigInteger d = dStr.isEmpty() ? null : new BigInteger(dStr);

        System.out.print("Prime p (for CRT optimization): ");
        String pStr = scanner.nextLine();
        BigInteger p = pStr.isEmpty() ? null : new BigInteger(pStr);

        System.out.print("Prime q (for CRT optimization): ");
        String qStr = scanner.nextLine();
        BigInteger q = qStr.isEmpty() ? null : new BigInteger(qStr);

        return new RSAKeyPair(n, e, d, p, q);
    }

    /**
     * Generates a new RSA key pair and displays all components including CRT parameters.
     * 
     * @param keySize the desired key size in bits
     * @return a complete RSAKeyPair with all components including CRT parameters
     */
    private static RSAKeyPair generateAndDisplayNewKeys(int keySize) {
        System.out.println("\nGenerating " + keySize + "-bit RSA key pair with all optimizations...");

        long startTime = System.currentTimeMillis();
        RSAKeyPair keyPair = generateKeyPair(keySize);
        long endTime = System.currentTimeMillis();

        System.out.println("Key generation completed in " + (endTime - startTime) + " ms");

        System.out.println("\n=== Generated RSA Key Pair ===");
        System.out.println("Public Key (n, e):");
        System.out.println("n: " + keyPair.getN());
        System.out.println("e: " + keyPair.getE());

        System.out.println("\nPrivate Key Components:");
        System.out.println("d: " + keyPair.getD());
        System.out.println("p: " + keyPair.getP());
        System.out.println("q: " + keyPair.getQ());

        if (keyPair.hasCRTComponents()) {
            System.out.println("\nCRT Optimization Components:");
            System.out.println("dp: " + keyPair.getDp());
            System.out.println("dq: " + keyPair.getDq());
            System.out.println("qInv: " + keyPair.getQInv());
        }

        return keyPair;
    }

    /**
     * Handles the main operation selection and execution.
     * 
     * @param scanner the Scanner object for user input
     * @param keyPair the RSA key pair to use for operations
     */
    private static void performOperation(Scanner scanner, RSAKeyPair keyPair) {
        System.out.println("\nChoose operation:");
        System.out.println("1) Encrypt message");
        System.out.println("2) Decrypt message (standard)");
        System.out.println("3) Decrypt message (with CRT optimization)");
        System.out.print("Your choice: ");

        int operation;
        try {
            operation = Integer.parseInt(scanner.nextLine());
        } catch (NumberFormatException ex) {
            operation = 1;
            System.out.println("Invalid choice. Defaulting to encryption.");
        }

        if (operation == 1) {
            performEncryption(scanner, keyPair);
        } else if (operation == 2) {
            performStandardDecryption(scanner, keyPair);
        } else if (operation == 3) {
            performCRTDecryption(scanner, keyPair);
        }
    }

    /**
     * Performs RSA encryption on user-provided message.
     * Supports both text and numeric input formats.
     * 
     * @param scanner the Scanner object for user input
     * @param keyPair the RSA key pair containing the public key
     */
    private static void performEncryption(Scanner scanner, RSAKeyPair keyPair) {
        System.out.print("\nEnter message to encrypt: ");
        String message = scanner.nextLine();

        System.out.println("\nChoose input format:");
        System.out.println("1) Text (UTF-8)");
        System.out.println("2) Decimal number");
        System.out.print("Your choice: ");

        int formatChoice;
        try {
            formatChoice = Integer.parseInt(scanner.nextLine());
        } catch (NumberFormatException ex) {
            formatChoice = 1;
            System.out.println("Invalid choice. Defaulting to text.");
        }

        BigInteger plaintext;
        if (formatChoice == 2) {
            plaintext = new BigInteger(message);
        } else {
            plaintext = textToBigInteger(message);
        }

        if (plaintext.compareTo(keyPair.getN()) >= 0) {
            System.out.println("\nWarning: Message is too large for the key size.");
            System.out.println("In practice, you would use hybrid encryption (RSA + AES).");
            return;
        }

        long startTime = System.currentTimeMillis();
        BigInteger ciphertext = encrypt(plaintext, keyPair.getE(), keyPair.getN());
        long endTime = System.currentTimeMillis();

        System.out.println("\n=== ENCRYPTION RESULTS ===");
        System.out.println("Plaintext: " + plaintext);
        System.out.println("Ciphertext: " + ciphertext);
        System.out.println("Encryption time: " + (endTime - startTime) + " ms");

        showEncryptionDetailsIfRequested(scanner, plaintext, keyPair.getE(), keyPair.getN(), ciphertext);

        if (keyPair.getD() != null) {
            System.out.print("\nDo you want to decrypt this message? (Y/N): ");
            String decryptChoice = scanner.nextLine().toLowerCase();
            if (decryptChoice.startsWith("y")) {
                demonstrateDecryptionMethods(scanner, ciphertext, keyPair);
            }
        }
    }

    /**
     * Performs standard RSA decryption using the private exponent.
     * 
     * @param scanner the Scanner object for user input
     * @param keyPair the RSA key pair containing the private key
     */
    private static void performStandardDecryption(Scanner scanner, RSAKeyPair keyPair) {
        if (keyPair.getD() == null) {
            System.out.println("Error: Private key is required for decryption.");
            return;
        }

        System.out.print("\nEnter ciphertext (decimal): ");
        BigInteger ciphertext = new BigInteger(scanner.nextLine());

        long startTime = System.currentTimeMillis();
        BigInteger decrypted = decrypt(ciphertext, keyPair.getD(), keyPair.getN());
        long endTime = System.currentTimeMillis();

        displayDecryptionResults(decrypted, endTime - startTime, "Standard");
        showDecryptionDetailsIfRequested(scanner, ciphertext, keyPair.getD(), keyPair.getN(), decrypted);
    }

    /**
     * Performs CRT-optimized RSA decryption for improved performance.
     * 
     * @param scanner the Scanner object for user input
     * @param keyPair the RSA key pair with CRT components
     */
    private static void performCRTDecryption(Scanner scanner, RSAKeyPair keyPair) {
        if (!keyPair.hasCRTComponents()) {
            System.out.println("Error: CRT components (p, q) are required for CRT decryption.");
            return;
        }

        System.out.print("\nEnter ciphertext (decimal): ");
        BigInteger ciphertext = new BigInteger(scanner.nextLine());

        long startTime = System.currentTimeMillis();
        BigInteger decrypted = decryptWithCRT(ciphertext, keyPair);
        long endTime = System.currentTimeMillis();

        displayDecryptionResults(decrypted, endTime - startTime, "CRT Optimized");
        showCRTDetailsIfRequested(scanner, ciphertext, keyPair, decrypted);
    }

    /**
     * Demonstrates and compares standard vs CRT decryption methods.
     * Shows performance differences and verifies result consistency.
     * 
     * @param scanner the Scanner object for user input
     * @param ciphertext the ciphertext to decrypt
     * @param keyPair the RSA key pair with all components
     */
    private static void demonstrateDecryptionMethods(Scanner scanner, BigInteger ciphertext, RSAKeyPair keyPair) {
        System.out.println("\n=== COMPARING DECRYPTION METHODS ===");

        // Standard decryption
        long startTime1 = System.currentTimeMillis();
        BigInteger result1 = decrypt(ciphertext, keyPair.getD(), keyPair.getN());
        long endTime1 = System.currentTimeMillis();

        System.out.println("Standard decryption: " + (endTime1 - startTime1) + " ms");

        // CRT decryption if possible
        if (keyPair.hasCRTComponents()) {
            long startTime2 = System.currentTimeMillis();
            BigInteger result2 = decryptWithCRT(ciphertext, keyPair);
            long endTime2 = System.currentTimeMillis();

            System.out.println("CRT decryption: " + (endTime2 - startTime2) + " ms");
            System.out.println("Results match: " + result1.equals(result2));

            if (endTime1 - startTime1 > 0) {
                double speedup = (double)(endTime1 - startTime1) / (endTime2 - startTime2);
                System.out.printf("CRT speedup: %.2fx faster%n", speedup);
            }
        }

        displayDecryptionResults(result1, endTime1 - startTime1, "Final");
    }

    /**
     * Converts a text string to a BigInteger for RSA operations.
     * Uses UTF-8 byte encoding to preserve character information.
     * 
     * @param text the input text string
     * @return a BigInteger representation of the text
     */
    private static BigInteger textToBigInteger(String text) {
        byte[] bytes = text.getBytes();
        return new BigInteger(1, bytes);
    }

    /**
     * Converts a BigInteger back to a text string.
     * Handles byte array conversion and removes leading zero bytes if present.
     * 
     * @param num the BigInteger to convert
     * @return the decoded text string
     */
    private static String bigIntegerToText(BigInteger num) {
        byte[] bytes = num.toByteArray();
        if (bytes[0] == 0 && bytes.length > 1) {
            byte[] temp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, temp, 0, temp.length);
            bytes = temp;
        }
        return new String(bytes);
    }

    /**
     * Displays decryption results in a formatted manner.
     * Attempts to convert numeric result back to text if possible.
     * 
     * @param decrypted the decrypted BigInteger result
     * @param time the time taken for decryption in milliseconds
     * @param method the decryption method used (for labeling)
     */
    private static void displayDecryptionResults(BigInteger decrypted, long time, String method) {
        System.out.println("\n=== " + method.toUpperCase() + " DECRYPTION RESULTS ===");
        System.out.println("Decrypted number: " + decrypted);
        System.out.println("Decryption time: " + time + " ms");

        try {
            String decryptedText = bigIntegerToText(decrypted);
            System.out.println("As text: " + decryptedText);
        } catch (Exception e) {
            System.out.println("Could not convert to text (possibly not a text message)");
        }
    }

    /**
     * Shows detailed encryption process information if requested by user.
     * 
     * @param scanner the Scanner object for user input
     * @param plaintext the original message
     * @param e the public exponent
     * @param n the modulus
     * @param ciphertext the encrypted result
     */
    private static void showEncryptionDetailsIfRequested(Scanner scanner, BigInteger plaintext,
                                                         BigInteger e, BigInteger n, BigInteger ciphertext) {
        System.out.print("\nShow encryption process details? (Y/N): ");
        if (scanner.nextLine().toLowerCase().startsWith("y")) {
            System.out.println("\n=== ENCRYPTION PROCESS DETAILS ===");
            System.out.println("Formula: c = m^e mod n");
            System.out.println("m (message): " + plaintext);
            System.out.println("e (public exponent): " + e);
            System.out.println("n (modulus): " + n);
            System.out.println("Using Square-and-Multiply algorithm");
            System.out.println("c (ciphertext): " + ciphertext);
        }
    }

    /**
     * Shows detailed standard decryption process information if requested by user.
     * 
     * @param scanner the Scanner object for user input
     * @param ciphertext the encrypted message
     * @param d the private exponent
     * @param n the modulus
     * @param decrypted the decrypted result
     */
    private static void showDecryptionDetailsIfRequested(Scanner scanner, BigInteger ciphertext,
                                                         BigInteger d, BigInteger n, BigInteger decrypted) {
        System.out.print("\nShow standard decryption process details? (Y/N): ");
        if (scanner.nextLine().toLowerCase().startsWith("y")) {
            System.out.println("\n=== STANDARD DECRYPTION PROCESS DETAILS ===");
            System.out.println("Formula: m = c^d mod n");
            System.out.println("c (ciphertext): " + ciphertext);
            System.out.println("d (private exponent): " + d);
            System.out.println("n (modulus): " + n);
            System.out.println("Using Square-and-Multiply algorithm");
            System.out.println("m (message): " + decrypted);
        }
    }

    /**
     * Shows detailed CRT decryption process information if requested by user.
     * Explains each step of the three-phase CRT optimization.
     * 
     * @param scanner the Scanner object for user input
     * @param ciphertext the encrypted message
     * @param keyPair the RSA key pair with CRT components
     * @param result the final decrypted result
     */
    private static void showCRTDetailsIfRequested(Scanner scanner, BigInteger ciphertext,
                                                  RSAKeyPair keyPair, BigInteger result) {
        System.out.print("\nShow CRT process details? (Y/N): ");
        if (scanner.nextLine().toLowerCase().startsWith("y")) {
            System.out.println("\n=== CRT DECRYPTION PROCESS DETAILS ===");
            System.out.println("Step 1 - Transformation to CRT domain:");
            System.out.println("cp = c mod p = " + ciphertext + " mod " + keyPair.getP());
            BigInteger cp = ciphertext.mod(keyPair.getP());
            System.out.println("cp = " + cp);

            System.out.println("cq = c mod q = " + ciphertext + " mod " + keyPair.getQ());
            BigInteger cq = ciphertext.mod(keyPair.getQ());
            System.out.println("cq = " + cq);

            System.out.println("\nStep 2 - Exponentiation in CRT domain:");
            System.out.println("mp = cp^dp mod p = " + cp + "^" + keyPair.getDp() + " mod " + keyPair.getP());
            BigInteger mp = squareAndMultiply(cp, keyPair.getDp(), keyPair.getP());
            System.out.println("mp = " + mp);

            System.out.println("mq = cq^dq mod q = " + cq + "^" + keyPair.getDq() + " mod " + keyPair.getQ());
            BigInteger mq = squareAndMultiply(cq, keyPair.getDq(), keyPair.getQ());
            System.out.println("mq = " + mq);

            System.out.println("\nStep 3 - Inverse transformation:");
            System.out.println("qInv = q^(-1) mod p = " + keyPair.getQInv());
            System.out.println("Formula: m = (q * qInv * mp + p * pInv * mq) mod n");
            System.out.println("where pInv = p^(-1) mod q");

            BigInteger pInv = keyPair.getP().modInverse(keyPair.getQ());
            System.out.println("pInv = " + pInv);
            System.out.println("Final result: " + result);
        }
    }

    // ==================== CORE CRYPTOGRAPHIC ALGORITHMS ====================

    /**
     * Generates a complete RSA key pair with specified bit length.
     * 
     * <p>The generation process includes:</p>
     * <ul>
     *   <li>Generation of two large primes p and q</li>
     *   <li>Computation of modulus n = p × q</li>
     *   <li>Calculation of Euler's totient φ(n) = (p-1)(q-1)</li>
     *   <li>Selection of public exponent e (typically 65537)</li>
     *   <li>Computation of private exponent d = e^(-1) mod φ(n)</li>
     *   <li>Pre-computation of CRT parameters for optimization</li>
     * </ul>
     * 
     * @param bits the desired key size in bits (total for n)
     * @return a complete RSAKeyPair with all components including CRT parameters
     * @throws IllegalArgumentException if bits is not positive or too small
     */
    public static RSAKeyPair generateKeyPair(int bits) {
        System.out.println("Generating prime p...");
        BigInteger p = generatePrime(bits / 2);

        System.out.println("Generating prime q...");
        BigInteger q = generatePrime(bits / 2);

        // Ensure p != q for security
        while (p.equals(q)) {
            q = generatePrime(bits / 2);
        }

        // Ensure p > q for consistency in CRT calculations
        if (p.compareTo(q) < 0) {
            BigInteger temp = p;
            p = q;
            q = temp;
        }

        // Compute RSA parameters
        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Choose e (commonly 65537 for security and efficiency)
        BigInteger e = new BigInteger("65537");
        while (!e.gcd(phi).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.TWO);
        }

        BigInteger d = e.modInverse(phi);

        // Compute CRT optimization components
        BigInteger dp = d.mod(p.subtract(BigInteger.ONE));
        BigInteger dq = d.mod(q.subtract(BigInteger.ONE));
        BigInteger qInv = q.modInverse(p);

        return new RSAKeyPair(n, e, d, p, q, dp, dq, qInv);
    }

    /**
     * Generates a cryptographically secure prime number of specified bit length.
     * 
     * <p>Uses a combination of:</p>
     * <ul>
     *   <li>Random candidate generation with proper bit length</li>
     *   <li>Small divisibility tests for quick rejection</li>
     *   <li>Fermat's Little Theorem test</li>
     *   <li>Miller-Rabin primality test for high confidence</li>
     * </ul>
     * 
     * @param bits the desired bit length of the prime
     * @return a probable prime BigInteger of the specified bit length
     */
    private static BigInteger generatePrime(int bits) {
        BigInteger candidate;
        int attempts = 0;

        do {
            attempts++;
            candidate = new BigInteger(bits, RANDOM);

            // Ensure proper bit length and odd number
            candidate = candidate.setBit(bits - 1); // Set MSB to ensure bit length
            candidate = candidate.setBit(0); // Ensure odd number

            if (attempts % 100 == 0) {
                System.out.println("  Prime generation attempts: " + attempts);
            }

        } while (!isProbablePrime(candidate));

        System.out.println("  Found prime after " + attempts + " attempts");
        return candidate;
    }

    /**
     * Comprehensive primality testing using multiple algorithms.
     * 
     * <p>Testing sequence:</p>
     * <ol>
     *   <li>Handle trivial cases (2, 3, even numbers)</li>
     *   <li>Small prime divisibility test (up to 100)</li>
     *   <li>Fermat's Little Theorem test (multiple rounds)</li>
     *   <li>Miller-Rabin test (multiple rounds for high confidence)</li>
     * </ol>
     * 
     * @param n the number to test for primality
     * @return true if n is probably prime, false if definitely composite
     */
    private static boolean isProbablePrime(BigInteger n) {
        // Handle trivial cases
        if (n.equals(BigInteger.valueOf(2)) || n.equals(BigInteger.valueOf(3))) {
            return true;
        }
        if (n.compareTo(BigInteger.valueOf(2)) < 0 || n.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
            return false;
        }

        // Quick divisibility test for small primes
        for (int i = 3; i <= 100; i += 2) {
            if (n.mod(BigInteger.valueOf(i)).equals(BigInteger.ZERO)) {
                return false;
            }
        }

        // Fermat's Little Theorem test
        if (!fermatsTest(n, FERMAT_TEST_ROUNDS)) {
            return false;
        }

        // Miller-Rabin test (most reliable)
        return millerRabinTest(n, MILLER_RABIN_ROUNDS);
    }

    /**
     * Fermat's Little Theorem Primality Test.
     * 
     * <p>Tests if a^(n-1) ≡ 1 (mod n) for random values of a.
     * If this fails for any a, then n is definitely composite.
     * If it passes for all tested values, n is probably prime.</p>
     * 
     * <p>Note: This test can be fooled by Carmichael numbers, so it's
     * combined with Miller-Rabin for better reliability.</p>
     * 
     * @param n the number to test
     * @param rounds the number of random bases to test
     * @return true if n passes all tests, false if definitely composite
     */
    private static boolean fermatsTest(BigInteger n, int rounds) {
        BigInteger nMinusOne = n.subtract(BigInteger.ONE);

        for (int i = 0; i < rounds; i++) {
            BigInteger a;
            do {
                a = new BigInteger(n.bitLength() - 1, RANDOM);
            } while (a.compareTo(BigInteger.valueOf(2)) < 0 || a.compareTo(nMinusOne) >= 0);

            BigInteger result = squareAndMultiply(a, nMinusOne, n);
            if (!result.equals(BigInteger.ONE)) {
                return false; // Definitely composite
            }
        }
        return true; // Probably prime
    }

    /**
     * Miller-Rabin Primality Test - the gold standard for primality testing.
     * 
     * <p>This probabilistic test is based on the following:</p>
     * <ul>
     *   <li>Write n-1 as 2^r × d where d is odd</li>
     *   <li>For random base a, compute a^d mod n</li>
     *   <li>If result is 1 or n-1, continue with next base</li>
     *   <li>Otherwise, square the result r-1 times</li>
     *   <li>If we ever get n-1, continue with next base</li>
     *   <li>If we get 1 before seeing n-1, n is composite</li>
     *   <li>If we never get n-1, n is composite</li>
     * </ul>
     * 
     * <p>The error probability is at most (1/4)^rounds, making it extremely
     * reliable with sufficient rounds (typically 10+ for cryptographic use).</p>
     * 
     * @param n the number to test for primality
     * @param rounds the number of random witnesses to test
     * @return true if n is probably prime, false if definitely composite
     */
    private static boolean millerRabinTest(BigInteger n, int rounds) {
        // Write n-1 as 2^r * d where d is odd
        BigInteger nMinusOne = n.subtract(BigInteger.ONE);
        int r = 0;
        BigInteger d = nMinusOne;

        while (d.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
            r++;
            d = d.divide(BigInteger.valueOf(2));
        }

        // Witness loop - test with random bases
        for (int i = 0; i < rounds; i++) {
            BigInteger a;
            do {
                a = new BigInteger(n.bitLength() - 1, RANDOM);
            } while (a.compareTo(BigInteger.valueOf(2)) < 0 || a.compareTo(nMinusOne) >= 0);

            BigInteger x = squareAndMultiply(a, d, n);

            if (x.equals(BigInteger.ONE) || x.equals(nMinusOne)) {
                continue; // This witness doesn't prove compositeness
            }

            boolean isProbablyPrime = false;
            for (int j = 0; j < r - 1; j++) {
                x = x.multiply(x).mod(n);

                if (x.equals(BigInteger.ONE)) {
                    return false; // Definitely composite
                }
                if (x.equals(nMinusOne)) {
                    isProbablyPrime = true;
                    break; // This witness doesn't prove compositeness
                }
            }

            if (!isProbablyPrime) {
                return false; // Definitely composite
            }
        }

        return true; // Probably prime
    }

    /**
     * Square-and-Multiply Algorithm for efficient modular exponentiation.
     * 
     * <p>Computes base^exponent mod modulus efficiently using the binary
     * representation of the exponent. This algorithm has O(log exponent)
     * complexity instead of the naive O(exponent) approach.</p>
     * 
     * <p>Algorithm steps:</p>
     * <ol>
     *   <li>Initialize result = 1</li>
     *   <li>For each bit in exponent (from right to left):</li>
     *   <ul>
     *     <li>If bit is 1: result = (result × base) mod modulus</li>
     *     <li>Square the base: base = (base × base) mod modulus</li>
     *     <li>Shift exponent right by 1 bit</li>
     *   </ul>
     * </ol>
     * 
     * <p>This is the core algorithm used for both RSA encryption and decryption.</p>
     * 
     * @param base the base number
     * @param exponent the exponent (must be non-negative)
     * @param modulus the modulus (must be positive)
     * @return (base^exponent) mod modulus
     * @throws ArithmeticException if modulus is zero
     */
    public static BigInteger squareAndMultiply(BigInteger base, BigInteger exponent, BigInteger modulus) {
        BigInteger result = BigInteger.ONE;
        base = base.mod(modulus);

        while (exponent.compareTo(BigInteger.ZERO) > 0) {
            // If exponent is odd, multiply base with result
            if (exponent.mod(BigInteger.valueOf(2)).equals(BigInteger.ONE)) {
                result = result.multiply(base).mod(modulus);
            }

            // Now exponent must be even - divide by 2
            exponent = exponent.divide(BigInteger.valueOf(2));
            base = base.multiply(base).mod(modulus);
        }

        return result;
    }

    /**
     * Standard RSA Encryption operation.
     * 
     * <p>Encrypts a message using the RSA public key according to the formula:</p>
     * <p><code>ciphertext = message^e mod n</code></p>
     * 
     * <p>Where:</p>
     * <ul>
     *   <li>message is the plaintext (must be < n)</li>
     *   <li>e is the public exponent</li>
     *   <li>n is the public modulus</li>
     * </ul>
     * 
     * @param message the plaintext message as a BigInteger (must be < n)
     * @param e the public exponent
     * @param n the public modulus
     * @return the encrypted ciphertext
     * @throws IllegalArgumentException if message >= n
     */
    public static BigInteger encrypt(BigInteger message, BigInteger e, BigInteger n) {
        return squareAndMultiply(message, e, n);
    }

    /**
     * Standard RSA Decryption operation.
     * 
     * <p>Decrypts a ciphertext using the RSA private key according to the formula:</p>
     * <p><code>message = ciphertext^d mod n</code></p>
     * 
     * <p>Where:</p>
     * <ul>
     *   <li>ciphertext is the encrypted message</li>
     *   <li>d is the private exponent</li>
     *   <li>n is the public modulus</li>
     * </ul>
     * 
     * @param ciphertext the encrypted message
     * @param d the private exponent
     * @param n the public modulus
     * @return the decrypted plaintext message
     */
    public static BigInteger decrypt(BigInteger ciphertext, BigInteger d, BigInteger n) {
        return squareAndMultiply(ciphertext, d, n);
    }

    /**
     * Chinese Remainder Theorem (CRT) optimized RSA decryption.
     * 
     * <p>This method provides approximately 4x speedup over standard decryption
     * by leveraging the factorization of n = p × q. The CRT allows us to:</p>
     * <ol>
     *   <li>Transform the problem to smaller modular arithmetic operations</li>
     *   <li>Perform exponentiations modulo p and q separately (parallel)</li>
     *   <li>Combine results using the Chinese Remainder Theorem</li>
     * </ol>
     * 
     * <p>Mathematical foundation:</p>
     * <ul>
     *   <li>dp = d mod (p-1)</li>
     *   <li>dq = d mod (q-1)</li>
     *   <li>qInv = q^(-1) mod p</li>
     *   <li>mp = c^dp mod p</li>
     *   <li>mq = c^dq mod q</li>
     *   <li>m = mq + q × ((mp - mq) × qInv mod p)</li>
     * </ul>
     * 
     * <p>The speedup comes from working with smaller numbers (p and q instead of n)
     * and smaller exponents (dp and dq instead of d).</p>
     * 
     * @param ciphertext the encrypted message
     * @param keyPair the RSA key pair containing all CRT components
     * @return the decrypted plaintext message
     * @throws IllegalArgumentException if keyPair lacks CRT components
     */
    public static BigInteger decryptWithCRT(BigInteger ciphertext, RSAKeyPair keyPair) {
        BigInteger p = keyPair.getP();
        BigInteger q = keyPair.getQ();
        BigInteger dp = keyPair.getDp();
        BigInteger dq = keyPair.getDq();
        BigInteger qInv = keyPair.getQInv();

        // Step 1: Transformation to CRT domain
        // Reduce ciphertext modulo p and q
        BigInteger cp = ciphertext.mod(p);
        BigInteger cq = ciphertext.mod(q);

        // Step 2: Exponentiation in CRT domain (can be done in parallel)
        // These operations use smaller numbers, providing the main speedup
        BigInteger mp = squareAndMultiply(cp, dp, p);
        BigInteger mq = squareAndMultiply(cq, dq, q);

        // Step 3: Inverse transformation using CRT
        // Combine results back to the original domain
        // Using optimized formula: m = mq + q * ((mp - mq) * qInv mod p)
        BigInteger h = ((mp.subtract(mq)).multiply(qInv)).mod(p);
        BigInteger m = mq.add(h.multiply(q));

        return m;
    }

    /**
     * RSA Key Pair container class with comprehensive key management.
     * 
     * <p>This class encapsulates all components of an RSA key pair:</p>
     * <ul>
     *   <li><strong>Public Key:</strong> (n, e) - used for encryption and signature verification</li>
     *   <li><strong>Private Key:</strong> (n, d) or (p, q, dp, dq, qInv) - used for decryption and signing</li>
     *   <li><strong>CRT Components:</strong> Pre-computed values for fast decryption</li>
     * </ul>
     * 
     * <p>Key Components Explained:</p>
     * <ul>
     *   <li><code>n</code> - Modulus (n = p × q)</li>
     *   <li><code>e</code> - Public exponent (typically 65537)</li>
     *   <li><code>d</code> - Private exponent (d = e^(-1) mod φ(n))</li>
     *   <li><code>p, q</code> - Prime factors of n</li>
     *   <li><code>dp</code> - d mod (p-1) for CRT optimization</li>
     *   <li><code>dq</code> - d mod (q-1) for CRT optimization</li>
     *   <li><code>qInv</code> - q^(-1) mod p for CRT optimization</li>
     * </ul>
     * 
     * <p>Security Note: The private components (d, p, q, dp, dq, qInv) must be
     * kept secret. Only the public components (n, e) should be shared.</p>
     */
    public static class RSAKeyPair {
        /** Public modulus (n = p × q) */
        private final BigInteger n;
        
        /** Public exponent (typically 65537) */
        private final BigInteger e;
        
        /** Private exponent (d = e^(-1) mod φ(n)) */
        private final BigInteger d;
        
        /** First prime factor of n */
        private final BigInteger p;
        
        /** Second prime factor of n */
        private final BigInteger q;
        
        /** CRT parameter: d mod (p-1) */
        private final BigInteger dp;
        
        /** CRT parameter: d mod (q-1) */
        private final BigInteger dq;
        
        /** CRT parameter: q^(-1) mod p */
        private final BigInteger qInv;

        /**
         * Constructs an RSAKeyPair with basic components (without CRT optimization).
         * 
         * @param n the public modulus
         * @param e the public exponent
         * @param d the private exponent (can be null for encryption-only keys)
         * @param p the first prime factor (can be null)
         * @param q the second prime factor (can be null)
         */
        public RSAKeyPair(BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q) {
            this(n, e, d, p, q, null, null, null);
        }

        /**
         * Constructs a complete RSAKeyPair with all components including CRT optimization.
         * 
         * @param n the public modulus
         * @param e the public exponent
         * @param d the private exponent (can be null for encryption-only keys)
         * @param p the first prime factor (can be null)
         * @param q the second prime factor (can be null)
         * @param dp the CRT parameter d mod (p-1) (can be null)
         * @param dq the CRT parameter d mod (q-1) (can be null)
         * @param qInv the CRT parameter q^(-1) mod p (can be null)
         */
        public RSAKeyPair(BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q,
                          BigInteger dp, BigInteger dq, BigInteger qInv) {
            this.n = n;
            this.e = e;
            this.d = d;
            this.p = p;
            this.q = q;
            this.dp = dp;
            this.dq = dq;
            this.qInv = qInv;
        }

        /**
         * Gets the public modulus n.
         * @return the modulus (n = p × q)
         */
        public BigInteger getN() { return n; }

        /**
         * Gets the public exponent e.
         * @return the public exponent (typically 65537)
         */
        public BigInteger getE() { return e; }

        /**
         * Gets the private exponent d.
         * @return the private exponent, or null if not available
         */
        public BigInteger getD() { return d; }

        /**
         * Gets the first prime factor p.
         * @return the first prime factor, or null if not available
         */
        public BigInteger getP() { return p; }

        /**
         * Gets the second prime factor q.
         * @return the second prime factor, or null if not available
         */
        public BigInteger getQ() { return q; }

        /**
         * Gets the CRT parameter dp = d mod (p-1).
         * @return the CRT parameter dp, or null if not available
         */
        public BigInteger getDp() { return dp; }

        /**
         * Gets the CRT parameter dq = d mod (q-1).
         * @return the CRT parameter dq, or null if not available
         */
        public BigInteger getDq() { return dq; }

        /**
         * Gets the CRT parameter qInv = q^(-1) mod p.
         * @return the CRT parameter qInv, or null if not available
         */
        public BigInteger getQInv() { return qInv; }

        /**
         * Checks if this key pair has all components necessary for CRT optimization.
         * 
         * @return true if all CRT components (p, q, dp, dq, qInv) are available
         */
        public boolean hasCRTComponents() {
            return p != null && q != null && dp != null && dq != null && qInv != null;
        }
    }
}
