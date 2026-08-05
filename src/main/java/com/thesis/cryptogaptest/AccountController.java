package com.thesis.cryptogaptest;

import com.thesis.cryptogaptest.Account;
import com.thesis.cryptogaptest.AccountNumberEncryptor;
import com.thesis.cryptogaptest.HashService;
import org.springframework.web.bind.annotation.*;

/**
 * REST Controller for Account Management
 * 
 * Demonstrates usage of cryptographic services:
 * - AccountNumberEncryptor: L4 JCA usage
 * - HashService: L4 raw MessageDigest usage
 */
@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    @GetMapping("/{id}")
    public Account getAccount(@PathVariable Long id) {
        // Mock implementation
        return new Account();
    }

    @PostMapping
    public Account createAccount(@RequestBody Account account) throws Exception {
        // Example: Encrypt account number before storage
        String encryptedAccountNumber = AccountNumberEncryptor.encryptWithECB(
            account.getAccountNumber(),
            "0123456789ABCDEF"  // 16-char key for AES-128
        );
        account.setAccountNumber(encryptedAccountNumber);
        
        // Example: Hash routing number
        String hashedRoutingNumber = HashService.hashWithSHA1(account.getRoutingNumber());
        
        return account;
    }

    @PutMapping("/{id}")
    public Account updateAccount(@PathVariable Long id, @RequestBody Account account) {
        return account;
    }

    @DeleteMapping("/{id}")
    public void deleteAccount(@PathVariable Long id) {
        // Deletion logic
    }

}
