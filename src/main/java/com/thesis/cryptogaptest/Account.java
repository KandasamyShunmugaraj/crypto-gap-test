package com.thesis.cryptogaptest;

import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Layer 2 — @Convert annotation points to broken encryptor
    // CBOMkit MISSES this — doesn't trace annotations into converter classes
    @Convert(converter = AccountNumberEncryptor.class)
    private String accountNumber;

    private String ownerName;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getAccountNumber() { return accountNumber; }
    public void setAccountNumber(String s) { this.accountNumber = s; }
    public String getOwnerName() { return ownerName; }
    public void setOwnerName(String s) { this.ownerName = s; }
}