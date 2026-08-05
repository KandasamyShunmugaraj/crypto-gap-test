package com.thesis.cryptogaptest;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

/**
 * FINDING L2: JPA Field-Level Encryption via @Convert Annotation
 * 
 * This entity demonstrates JPA converter-based encryption detection.
 * CBOMkit: ❌ DOES NOT DETECT (only scans raw JCA calls, not annotations)
 * SpringCryptoScanner: ✅ DETECTS with:
 *   - detection-rule=FIELD_LEVEL_ENCRYPTION_DETECTED
 *   - spring-layer=L2-JPAConverter
 *   - severity=MEDIUM
 *   - audit-required: verify AES-256-GCM (not ECB), no hardcoded key, use secrets manager
 */
@Entity
@Table(name = "accounts")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "account_holder_name")
    private String accountHolderName;

    // FINDING L2-1: JPA @Convert annotation for field-level encryption
    // Line 18: Field-level encryption via custom converter
    // CBOMkit: ❌ MISSES (does not parse annotations or @Convert attributes)
    // SpringCryptoScanner: ✅ DETECTS
    //   - Identifies the AccountNumberEncryptor converter
    //   - Audits the converter implementation for AES-GCM/ECB usage
    //   - Severity: MEDIUM (annotation-driven, requires converter audit)
    @Column(name = "account_number", length = 255)
    @Convert(converter = AccountNumberEncryptor.class)
    private String accountNumber;

    @Column(name = "created_at")
    private Long createdAt;

    @Column(name = "updated_at")
    private Long updatedAt;

    // FINDING L2-2: Another sensitive field with encryption
    // This demonstrates multiple annotation-driven encryption points
    @Column(name = "routing_number", length = 255)
    @Convert(converter = AccountNumberEncryptor.class)
    private String routingNumber;

}

/**
 * AUDIT NOTE for L2 Findings:
 * 
 * When @Convert(converter = X) is detected, SpringCryptoScanner must:
 * 1. Locate the converter class implementation
 * 2. Parse the converter's cryptographic operations
 * 3. Verify: Is it using AES-256-GCM? (✅ Good)
 *    Warning: Is it using AES-ECB? (❌ Bad)
 * 4. Verify: Is the key hardcoded? (❌ Bad)
 *    Recommended: Spring Vault / AWS Secrets Manager
 * 5. Report severity based on converter audit findings
 * 
 * CBOMkit cannot perform this multi-layer analysis.
 */
