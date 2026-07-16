package com.thesis.cryptogaptest;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Service
public class HashService {

    // Layer 4 — raw JCA call
    // SHA-1 is deprecated and broken
    // CBOMkit SHOULD detect this
    public byte[] weakHash(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(input.getBytes(StandardCharsets.UTF_8));
    }
}
