package com.thesis.cryptogaptest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Crypto Gap Test Application
 * 
 * This Spring Boot application serves as a test bed for comparing cryptographic
 * asset detection between CBOMkit and SpringCryptoScanner.
 * 
 * Repository: https://github.com/KandasamyShunmugaraj/crypto-gap-test
 * Tool: https://github.com/KandasamyShunmugaraj/spring-crypto-scanner
 * 
 * Thesis Author: Kandasamy S (M25AID042)
 * IIT Jodhpur
 */
@SpringBootApplication
public class CryptoGapTestApplication {

    public static void main(String[] args) {
        SpringApplication.run(CryptoGapTestApplication.class, args);
    }

}
