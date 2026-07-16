# Spring Boot Crypto Gap Test

**Thesis Research Project — IIT Jodhpur**  
**Researcher:** Kandasamy S | **Guide:** Dr. Bimal Mandal

## What this is

A controlled Spring Boot project demonstrating cryptographic weaknesses
across 4 architectural layers that CBOMkit cannot detect.

## The 4 layers

| Layer | File | Weakness | CBOMkit detects? |
|---|---|---|---|
| L4 — Raw JCA | HashService.java | SHA-1 deprecated | Yes |
| L3 — Spring Bean | SecurityConfig.java | BCrypt cost=4 (weak) | No |
| L2 — JPA @Convert | Account.java + AccountNumberEncryptor.java | AES/ECB field encryption | No |
| L1 — Config file | application.yml | JKS keystore + weak JWT secret | No |

## Tools included

### SpringCryptoScanner
Detects cryptographic weaknesses across all 4 layers.
```bash
mvn compile -q && mvn exec:java \
  -Dexec.mainClass="com.thesis.cryptogaptest.SpringCryptoScanner" \
  -Dexec.args="/path/to/spring-boot-project" \
  2>/dev/null
```

### AgilityScorer
Computes a quantitative crypto-agility score (0-10) for PQC migration readiness.
```bash
mvn compile -q && mvn exec:java \
  -Dexec.mainClass="com.thesis.cryptogaptest.AgilityScorer" \
  -Dexec.args="/path/to/dataset/projects" \
  2>/dev/null
```

## Key findings from dataset scan (10 real Spring Boot projects)

| Finding | Value |
|---|---|
| CBOMkit findings in spring-security-samples | 0 |
| SpringCryptoScanner findings in spring-security-samples | 2 CRITICAL |
| Average agility score across 10 projects | 5.3 / 10 |
| Projects below safe threshold (7/10) | 7 out of 10 (70%) |
| Baeldung tutorials score | 0.0/10 — 47 findings |
