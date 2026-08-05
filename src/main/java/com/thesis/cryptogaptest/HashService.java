package com.thesis.cryptogaptest;

import java.security.MessageDigest;

/**
 * FINDING L4: Raw JCA MessageDigest Usage
 * 
 * This class demonstrates SHA-1 usage, which is classically broken since 2017 SHAttered attack.
 * CBOMkit DETECTS this (L4 - Raw JCA Layer).
 * SpringCryptoScanner ALSO DETECTS with severity=HIGH, quantum-status=classicallyBroken.
 */
public class HashService {

    // FINDING L4-4: SHA-1 hash algorithm (BROKEN - HIGH SEVERITY)
    // CBOMkit: ✅ DETECTS via java.security.MessageDigest#getInstance()
    // SpringCryptoScanner: ✅ DETECTS with:
    //   - severity=HIGH
    //   - quantum-status=classicallyBroken
    //   - pq-replacement="SHA-256 or SHA-3 (NIST FIPS 180-4 / FIPS 202)"
    public static String hashWithSHA1(String input) throws Exception {
        // Line 16: SHA-1 MessageDigest creation (INSECURE)
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        
        byte[] messageDigest = md.digest(input.getBytes());
        
        // Convert to hex string
        StringBuilder sb = new StringBuilder();
        for (byte b : messageDigest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Recommended replacement: SHA-256 (quantum-safe, NIST standard)
    public static String hashWithSHA256(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageDigest = md.digest(input.getBytes());
        
        StringBuilder sb = new StringBuilder();
        for (byte b : messageDigest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Recommended replacement: SHA-3 (post-quantum resistant)
    public static String hashWithSHA3(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA3-256");
        byte[] messageDigest = md.digest(input.getBytes());
        
        StringBuilder sb = new StringBuilder();
        for (byte b : messageDigest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
