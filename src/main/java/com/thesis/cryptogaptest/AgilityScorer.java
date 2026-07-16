package com.thesis.cryptogaptest;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Stream;

public class AgilityScorer {

    static class AgilityReport {
        String project;
        int hardcodedAlgorithms = 0;
        int configurableAlgorithms = 0;
        int deprecatedAlgorithms = 0;
        int totalCryptoUsages = 0;
        int yamlCryptoConfigs = 0;
        int rotationSupport = 0;
        double score = 0.0;

        AgilityReport(String project) {
            this.project = project;
        }

        void compute() {
            if (totalCryptoUsages == 0) {
                score = 10.0; // no crypto = trivially agile
                return;
            }
            // Dimension 1: Abstraction (are algorithms behind variables?)
            double abstraction = configurableAlgorithms > 0
                    ? (double) configurableAlgorithms / totalCryptoUsages
                    : 0.0;

            // Dimension 2: Quantum Safety (no deprecated algorithms)
            double quantumSafety = 1.0 -
                    ((double) deprecatedAlgorithms / totalCryptoUsages);

            // Dimension 3: Configurability (crypto in config files)
            double configurability = yamlCryptoConfigs > 0 ? 0.5 : 0.0;

            // Dimension 4: Rotation Support (placeholder — future work)
            double rotation = rotationSupport > 0 ? 1.0 : 0.0;

            // Weighted score out of 10
            score = ((abstraction * 2.5) +
                    (quantumSafety * 4.0) +
                    (configurability * 2.0) +
                    (rotation * 1.5));

            score = Math.max(0, Math.min(10, score));
        }

        String risk() {
            if (score >= 7) return "LOW";
            if (score >= 4) return "MEDIUM";
            return "HIGH";
        }

        @Override
        public String toString() {
            return String.format(
                    "%-45s | Score: %4.1f/10 | Risk: %-6s | " +
                            "Deprecated: %d | Hardcoded: %d | Config: %d",
                    project, score, risk(),
                    deprecatedAlgorithms, hardcodedAlgorithms,
                    yamlCryptoConfigs);
        }
    }

    public static AgilityReport scoreProject(String projectPath)
            throws Exception {
        String projectName = new File(projectPath).getName();
        AgilityReport report = new AgilityReport(projectName);

        // Scan Java files
        try (Stream<Path> paths = Files.walk(Paths.get(projectPath))) {
            List<Path> javaFiles = paths
                    .filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> !p.getFileName().toString()
                            .equals("AgilityScorer.java"))
                    .filter(p -> !p.getFileName().toString()
                            .equals("SpringCryptoScanner.java"))
                    .toList();

            for (Path javaFile : javaFiles) {
                String content = new String(
                        Files.readAllBytes(javaFile));

                // Count crypto usages
                if (content.contains("Cipher.getInstance") ||
                        content.contains("MessageDigest.getInstance") ||
                        content.contains("BCryptPasswordEncoder") ||
                        content.contains("NimbusJwtDecoder") ||
                        content.contains("KeyPairGenerator")) {
                    report.totalCryptoUsages++;
                }

                // Count hardcoded algorithm strings
                if (content.contains("\"AES") ||
                        content.contains("\"RSA") ||
                        content.contains("\"SHA") ||
                        content.contains("\"DES") ||
                        content.contains("\"MD5")) {
                    report.hardcodedAlgorithms++;
                }

                // Count configurable (reading from @Value or properties)
                if (content.contains("@Value") &&
                        (content.contains("algorithm") ||
                                content.contains("secret") ||
                                content.contains("key"))) {
                    report.configurableAlgorithms++;
                }

                // Count deprecated
                if (content.contains("SHA-1") ||
                        content.contains("SHA1") ||
                        content.contains("MD5") ||
                        content.contains("DES") ||
                        content.contains("ECB")) {
                    report.deprecatedAlgorithms++;
                }

                // Count rotation support
                if (content.contains("KeyRotation") ||
                        content.contains("keyVersion") ||
                        content.contains("rotateKey")) {
                    report.rotationSupport++;
                }
            }
        }

        // Scan YAML
        Path yamlPath = Paths.get(projectPath,
                "src/main/resources/application.yml");
        Path propsPath = Paths.get(projectPath,
                "src/main/resources/application.properties");

        for (Path configPath : List.of(yamlPath, propsPath)) {
            if (Files.exists(configPath)) {
                String content = new String(
                        Files.readAllBytes(configPath));
                if (content.contains("ssl") ||
                        content.contains("jwt") ||
                        content.contains("secret") ||
                        content.contains("key-store")) {
                    report.yamlCryptoConfigs++;
                }
            }
        }

        report.compute();
        return report;
    }

    public static void main(String[] args) throws Exception {
        String datasetPath = args.length > 0
                ? args[0]
                : System.getProperty("user.home") +
                "/thesis/dataset/projects";

        System.out.println(
                "═══════════════════════════════════════════════" +
                        "══════════════════════════════════════");
        System.out.println(
                "  CRYPTO-AGILITY SCORE — Spring Boot Dataset");
        System.out.println(
                "  Thesis: Spring-Aware Cryptographic Asset " +
                        "Discovery | Kandasamy S | IIT Jodhpur");
        System.out.println(
                "═══════════════════════════════════════════════" +
                        "══════════════════════════════════════");
        System.out.println();

        File datasetDir = new File(datasetPath);
        File[] projects = datasetDir.listFiles(File::isDirectory);

        if (projects == null || projects.length == 0) {
            System.out.println("No projects found at: " + datasetPath);
            return;
        }

        double totalScore = 0;
        int highRisk = 0, mediumRisk = 0, lowRisk = 0;

        System.out.printf("%-45s | %-14s | %-8s | %-10s | %s%n",
                "Project", "Agility Score", "PQC Risk",
                "Deprecated", "Hardcoded");
        System.out.println("-".repeat(100));

        for (File project : projects) {
            AgilityReport report = scoreProject(
                    project.getAbsolutePath());
            System.out.println(report);
            totalScore += report.score;
            if (report.risk().equals("HIGH")) highRisk++;
            else if (report.risk().equals("MEDIUM")) mediumRisk++;
            else lowRisk++;
        }

        double avgScore = totalScore / projects.length;
        System.out.println("-".repeat(100));
        System.out.println();
        System.out.println("═══════════════════ SUMMARY ════════════════════");
        System.out.printf("  Projects scanned  : %d%n", projects.length);
        System.out.printf("  Average score     : %.1f / 10%n", avgScore);
        System.out.printf("  HIGH risk         : %d projects%n", highRisk);
        System.out.printf("  MEDIUM risk       : %d projects%n", mediumRisk);
        System.out.printf("  LOW risk          : %d projects%n", lowRisk);
        System.out.println("════════════════════════════════════════════════");
    }
}