package com.thesis.cryptogaptest;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * FINDING L4: Raw JCA Cipher Usage
 * 
 * This class demonstrates cryptographic patterns detectable by both CBOMkit and SpringCryptoScanner.
 * CBOMkit DETECTS all findings here (L4 - Raw JCA Layer).
 * SpringCryptoScanner ALSO DETECTS all findings here plus extended context.
 */
public class AccountNumberEncryptor {

    // FINDING L4-1: AES-ECB cipher mode (INSECURE - CRITICAL SEVERITY)
    // CBOMkit: ✅ DETECTS via javax.crypto.Cipher#getInstance()
    // SpringCryptoScanner: ✅ DETECTS with severity=CRITICAL, remediation guidance
    public static String encryptWithECB(String accountNumber, String key) throws Exception {
        // Line 17: This is the insecure AES/ECB/PKCS5Padding cipher creation
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        
        // Line 23: AES SecretKeySpec creation (L4 finding)
        // CBOMkit sees: SecretKeySpec with AES128
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), 0, 16, "AES");
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(accountNumber.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // FINDING L4-2: Another AES-ECB usage (demonstrating multiple occurrences)
    // CBOMkit: ✅ DETECTS at line 35
    // SpringCryptoScanner: ✅ DETECTS with source tracking
    public static String decryptWithECB(String encryptedAccountNumber, String key) throws Exception {
        // Line 35: Second AES/ECB/PKCS5Padding cipher instance
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        
        // Line 36: Another AES SecretKeySpec
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), 0, 16, "AES");
        
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedAccountNumber);
        return new String(cipher.doFinal(decodedBytes), StandardCharsets.UTF_8);
    }

    // FINDING L4-3: Secure AES-GCM (RECOMMENDED - for comparison)
    // This is the CORRECT implementation that should be used instead of ECB
    // CBOMkit: ✅ DETECTS the algorithm usage
    // SpringCryptoScanner: ✅ DETECTS and marks as quantum-safe, INFO severity
    public static String encryptWithGCM(String accountNumber, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), 0, 16, "AES");
        // Note: GCM requires additional IV handling (not shown for brevity)
        // cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
        return "";
    }
}
