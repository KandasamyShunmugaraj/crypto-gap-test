package com.thesis.cryptogaptest;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.expr.IntegerLiteralExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class SpringCryptoScanner {

    // Represents a single finding
    static class Finding {
        String rule;
        String file;
        int line;
        String detail;
        String layer;
        String severity;

        Finding(String rule, String file, int line,
                String detail, String layer, String severity) {
            this.rule = rule;
            this.file = file;
            this.line = line;
            this.detail = detail;
            this.layer = layer;
            this.severity = severity;
        }

        @Override
        public String toString() {
            return String.format("[%s] [%s] %s @ %s:%d — %s",
                    severity, layer, rule, file, line, detail);
        }
    }

    private final String projectPath;
    private final List<Finding> findings = new ArrayList<>();

    public SpringCryptoScanner(String projectPath) {
        this.projectPath = projectPath;
    }

    public void scan() throws Exception {
        System.out.println("==============================================");
        System.out.println(" Spring Crypto Scanner — Thesis Tool v1.0");
        System.out.println(" Scanning: " + projectPath);
        System.out.println("==============================================\n");

        // Walk all .java files
        try (Stream<Path> paths = Files.walk(Paths.get(projectPath))) {
            paths.filter(p -> p.toString().endsWith(".java"))
                    .forEach(p -> {
                        try { scanJavaFile(p.toFile()); }
                        catch (Exception e) {
                            System.err.println("Could not parse: " + p);
                        }
                    });
        }

        // Scan YAML config
        scanYamlFile(projectPath + "/src/main/resources/application.yml");

        // Scan pom.xml
        scanPomFile(projectPath + "/pom.xml");

        // Print results
        printReport();
    }

    // ─── Rule 1: BCrypt weak cost factor (Layer 3) ───────────────────────────
    private void checkBCrypt(CompilationUnit cu, String fileName) {
        cu.findAll(ObjectCreationExpr.class).forEach(expr -> {
            if (expr.getTypeAsString().equals("BCryptPasswordEncoder")) {
                if (!expr.getArguments().isEmpty()) {
                    expr.getArguments().get(0).ifIntegerLiteralExpr(lit -> {
                        int strength = Integer.parseInt(lit.asIntegerLiteralExpr().getValue());
                        if (strength < 10) {
                            findings.add(new Finding(
                                    "WEAK_BCRYPT_COST_FACTOR",
                                    fileName,
                                    expr.getBegin().map(p -> p.line).orElse(0),
                                    "BCryptPasswordEncoder strength=" + strength +
                                            " (minimum safe value is 10)",
                                    "L3-SpringSecurityBean",
                                    "HIGH"
                            ));
                        }
                    });
                }
            }
        });
    }

    // ─── Rule 2: NimbusJwtDecoder missing algorithm whitelist (Layer 3) ──────
    private void checkJwtDecoder(CompilationUnit cu, String fileName) {
        cu.findAll(MethodCallExpr.class).forEach(expr -> {
            if (expr.getNameAsString().equals("withSecretKey") ||
                    expr.getNameAsString().equals("withPublicKey")) {
                // Check if setJwsAlgorithms is NOT chained
                String fullExpr = expr.toString();
                if (!fullExpr.contains("setJwsAlgorithms") &&
                        !fullExpr.contains("jwsAlgorithm")) {
                    findings.add(new Finding(
                            "MISSING_JWT_ALGORITHM_WHITELIST",
                            fileName,
                            expr.getBegin().map(p -> p.line).orElse(0),
                            "NimbusJwtDecoder built without explicit algorithm " +
                                    "whitelist — vulnerable to algorithm confusion attack",
                            "L3-SpringSecurityBean",
                            "CRITICAL"
                    ));
                }
            }
        });
    }

    // ─── Rule 3: @Convert annotation pointing to encryptor (Layer 2) ─────────
    private void checkConvertAnnotation(CompilationUnit cu, String fileName) {
        cu.findAll(FieldDeclaration.class).forEach(field -> {
            field.getAnnotations().forEach(ann -> {
                if (ann.getNameAsString().equals("Convert")) {
                    findings.add(new Finding(
                            "FIELD_LEVEL_ENCRYPTION_DETECTED",
                            fileName,
                            field.getBegin().map(p -> p.line).orElse(0),
                            "@Convert annotation found on field '" +
                                    field.getVariable(0).getNameAsString() +
                                    "' — verify encryptor algorithm and key management. " +
                                    "CBOMkit cannot trace this annotation to its implementation.",
                            "L2-JPAConverter",
                            "MEDIUM"
                    ));
                }
            });
        });
    }

    // ─── Rule 4: Weak algorithm strings in any Java file (Layer 4 enhanced) ──
    private void checkWeakAlgorithms(CompilationUnit cu, String fileName) {
        cu.findAll(StringLiteralExpr.class).forEach(str -> {
            String val = str.asString().toUpperCase();
            if (val.contains("ECB")) {
                findings.add(new Finding(
                        "WEAK_CIPHER_MODE_ECB",
                        fileName,
                        str.getBegin().map(p -> p.line).orElse(0),
                        "ECB cipher mode detected: '" + str.asString() +
                                "' — ECB is deterministic and reveals data patterns",
                        "L4-RawJCA",
                        "CRITICAL"
                ));
            }
            if (val.equals("SHA-1") || val.equals("SHA1") ||
                    val.equals("MD5") || val.equals("DES")) {
                findings.add(new Finding(
                        "DEPRECATED_ALGORITHM",
                        fileName,
                        str.getBegin().map(p -> p.line).orElse(0),
                        "Deprecated algorithm: '" + str.asString() + "'",
                        "L4-RawJCA",
                        "HIGH"
                ));
            }
        });
    }

    // ─── Rule 5: YAML config scanning (Layer 1) ───────────────────────────────
    private void scanYamlFile(String yamlPath) {
        File f = new File(yamlPath);
        if (!f.exists()) return;
        try {
            List<String> lines = Files.readAllLines(f.toPath());
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i).trim().toLowerCase();
                int lineNum = i + 1;

                if (line.contains("key-store-type") && line.contains("jks")) {
                    findings.add(new Finding(
                            "DEPRECATED_KEYSTORE_TYPE",
                            "application.yml",
                            lineNum,
                            "JKS keystore type is deprecated — use PKCS12",
                            "L1-ConfigFile",
                            "MEDIUM"
                    ));
                }
                if (line.contains("secret") && line.contains(":") &&
                        !line.trim().startsWith("#")) {
                    String val = line.split(":")[1].trim();
                    if (val.length() < 32 && !val.isEmpty()) {
                        findings.add(new Finding(
                                "WEAK_SECRET_IN_CONFIG",
                                "application.yml",
                                lineNum,
                                "Potentially weak secret in config: line too " +
                                        "short for cryptographic use (< 32 chars)",
                                "L1-ConfigFile",
                                "CRITICAL"
                        ));
                    }
                }
                if (line.contains("protocol") && line.contains("tls") &&
                        !line.contains("tlsv1.3")) {
                    findings.add(new Finding(
                            "TLS_VERSION_NOT_PINNED",
                            "application.yml",
                            lineNum,
                            "TLS protocol not pinned to TLSv1.3",
                            "L1-ConfigFile",
                            "MEDIUM"
                    ));
                }
            }
        } catch (Exception e) {
            System.err.println("Could not read YAML: " + e.getMessage());
        }
    }

    // ─── Rule 6: Maven dependency version check (Layer 1) ────────────────────
    private void scanPomFile(String pomPath) {
        File f = new File(pomPath);
        if (!f.exists()) return;
        try {
            String content = new String(Files.readAllBytes(f.toPath()));
            if (content.contains("bcprov-jdk15on")) {
                findings.add(new Finding(
                        "LEGACY_BOUNCY_CASTLE",
                        "pom.xml",
                        0,
                        "Legacy BouncyCastle artifact 'bcprov-jdk15on' detected " +
                                "— migrate to 'bcprov-jdk18on'",
                        "L1-MavenDependency",
                        "MEDIUM"
                ));
            }
            if (content.contains("nimbus-jose-jwt")) {
                findings.add(new Finding(
                        "NIMBUS_JWT_PRESENT",
                        "pom.xml",
                        0,
                        "nimbus-jose-jwt detected — verify version is not " +
                                "affected by CVE-2025-53864",
                        "L1-MavenDependency",
                        "INFO"
                ));
            }
        } catch (Exception e) {
            System.err.println("Could not read pom.xml: " + e.getMessage());
        }
    }

    // ─── Scan a single Java file ──────────────────────────────────────────────
    private void scanJavaFile(File file) throws Exception {
        // Skip the scanner itself to avoid false positives
        if (file.getName().equals("SpringCryptoScanner.java")) return;

        CompilationUnit cu = StaticJavaParser.parse(
                new FileInputStream(file));
        String fileName = file.getName();
        checkBCrypt(cu, fileName);
        checkJwtDecoder(cu, fileName);
        checkConvertAnnotation(cu, fileName);
        checkWeakAlgorithms(cu, fileName);
    }

    // ─── Print final report ───────────────────────────────────────────────────
    private void printReport() {
        System.out.println("\n══════════════════════════════════════════════");
        System.out.println(" SCAN RESULTS — " + findings.size() + " findings");
        System.out.println("══════════════════════════════════════════════\n");

        if (findings.isEmpty()) {
            System.out.println("No issues found.");
            return;
        }

        // Group by layer
        String[] layers = {
                "L1-ConfigFile", "L1-MavenDependency",
                "L2-JPAConverter", "L3-SpringSecurityBean", "L4-RawJCA"
        };

        for (String layer : layers) {
            List<Finding> layerFindings = findings.stream()
                    .filter(f -> f.layer.equals(layer))
                    .toList();
            if (!layerFindings.isEmpty()) {
                System.out.println("── " + layer + " ──────────────────────");
                layerFindings.forEach(f -> System.out.println("  " + f));
                System.out.println();
            }
        }

        // Summary
        long critical = findings.stream()
                .filter(f -> f.severity.equals("CRITICAL")).count();
        long high = findings.stream()
                .filter(f -> f.severity.equals("HIGH")).count();
        long medium = findings.stream()
                .filter(f -> f.severity.equals("MEDIUM")).count();

        System.out.println("══════════════════════════════════════════════");
        System.out.println(" SUMMARY");
        System.out.println(" CRITICAL : " + critical);
        System.out.println(" HIGH     : " + high);
        System.out.println(" MEDIUM   : " + medium);
        System.out.println("══════════════════════════════════════════════");
    }

    // ─── Entry point ──────────────────────────────────────────────────────────
    public static void main(String[] args) throws Exception {
        String projectPath = args.length > 0
                ? args[0]
                : System.getProperty("user.home") +
                "/thesis/crypto-gap-test";
        new SpringCryptoScanner(projectPath).scan();
    }
}