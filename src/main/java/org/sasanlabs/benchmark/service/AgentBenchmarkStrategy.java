package org.sasanlabs.benchmark.service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.sasanlabs.benchmark.model.BenchmarkResult;
import org.sasanlabs.benchmark.model.ExpectedIssue;
import org.sasanlabs.benchmark.model.Finding;
import org.sasanlabs.benchmark.model.ScannerFindings;
import org.springframework.stereotype.Service;

/**
 * Compares black-box agent findings against the CSV-backed application attack surface. Agent
 * findings must identify the endpoint, method, and at least one taxonomy axis, and must include
 * non-empty evidence to count as detected.
 */
@Service
public class AgentBenchmarkStrategy implements BenchmarkStrategy {

    private static final Logger LOGGER = LogManager.getLogger(AgentBenchmarkStrategy.class);

    private static final String UNSECURE_VARIANT = "UNSECURE";
    private static final String KEY_SEPARATOR = "::";
    private static final String AXIS_TYPE = "TYPE";
    private static final String AXIS_CWE = "CWE";
    private static final String AXIS_KEY = "KEY";

    private final IExpectedIssuesProvider expectedIssuesProvider;

    public AgentBenchmarkStrategy(IExpectedIssuesProvider expectedIssuesProvider) {
        this.expectedIssuesProvider = expectedIssuesProvider;
    }

    @Override
    public BenchmarkResult compare(ScannerFindings input) throws IOException {
        List<ExpectedIssue> expected =
                expectedIssuesProvider.getExpectedIssues().stream()
                        .filter(ExpectedIssue::isAgentMode)
                        .filter(
                                issue ->
                                        UNSECURE_VARIANT.equalsIgnoreCase(
                                                nullToEmpty(issue.getVariant())))
                        .collect(Collectors.toList());

        List<Finding> expectedRows = new ArrayList<>();
        Map<String, Set<Integer>> keyToExpected = buildExpectedIndex(expected, expectedRows);

        Set<Integer> detectedIndices = new LinkedHashSet<>();
        List<Finding> unmatchedItems = new ArrayList<>();
        Set<String> seenFindingSignatures = new HashSet<>();

        List<Finding> rawFindings =
                (input.getFindings() != null) ? input.getFindings() : new ArrayList<>();
        for (Finding finding : rawFindings) {
            if (finding == null) {
                continue;
            }
            String signature = findingSignature(finding);
            if (!seenFindingSignatures.add(signature)) {
                continue;
            }
            if (!hasEvidence(finding)) {
                unmatchedItems.add(finding);
                continue;
            }

            List<String> keys = keysForFinding(finding);
            if (keys.isEmpty()) {
                unmatchedItems.add(finding);
                continue;
            }

            Set<Integer> hits = new LinkedHashSet<>();
            for (String key : keys) {
                Set<Integer> rows = keyToExpected.get(key);
                if (rows != null) {
                    hits.addAll(rows);
                }
            }
            if (hits.isEmpty()) {
                unmatchedItems.add(finding);
            } else {
                detectedIndices.addAll(hits);
            }
        }

        List<Finding> missedItems = new ArrayList<>();
        for (int i = 0; i < expectedRows.size(); i++) {
            if (!detectedIndices.contains(i)) {
                missedItems.add(expectedRows.get(i));
            }
        }

        int totalExpected = expectedRows.size();
        int detected = detectedIndices.size();
        double coverage;
        if (totalExpected == 0) {
            LOGGER.warn(
                    "AGENT ground truth is empty; coverage cannot be computed and will be reported"
                            + " as 0.0");
            coverage = 0.0;
        } else {
            coverage = detected * 100.0 / totalExpected;
        }

        return new BenchmarkResult(
                input.getTool(),
                coverage,
                totalExpected,
                detected,
                missedItems.size(),
                unmatchedItems.size(),
                missedItems,
                unmatchedItems);
    }

    private static Map<String, Set<Integer>> buildExpectedIndex(
            List<ExpectedIssue> expected, List<Finding> rowsOut) {
        Map<String, Set<Integer>> keyToRows = new LinkedHashMap<>();
        Set<String> seenRows = new HashSet<>();
        for (ExpectedIssue issue : expected) {
            String endpoint = DastBenchmarkStrategy.normalizeUrl(issue.getEndpoint());
            String method = normalizeMethod(issue.getMethod());
            if (endpoint.isEmpty() || method.isEmpty()) {
                continue;
            }
            String rowSignature =
                    endpoint
                            + KEY_SEPARATOR
                            + method
                            + KEY_SEPARATOR
                            + nullToEmpty(issue.getCwe())
                            + KEY_SEPARATOR
                            + nullToEmpty(issue.getVulnerabilityType())
                            + KEY_SEPARATOR
                            + nullToEmpty(issue.getVulnerabilityKey());
            if (!seenRows.add(rowSignature)) {
                continue;
            }
            int rowIndex = rowsOut.size();
            rowsOut.add(toFinding(issue, endpoint, method));
            addExpectedKeys(keyToRows, rowIndex, endpoint, method, issue);
        }
        return keyToRows;
    }

    private static void addExpectedKeys(
            Map<String, Set<Integer>> keyToRows,
            int rowIndex,
            String endpoint,
            String method,
            ExpectedIssue issue) {
        String type = issue.getVulnerabilityType();
        if (type != null && !type.trim().isEmpty()) {
            addKey(keyToRows, typeKey(endpoint, method, type), rowIndex);
        }
        String cwe = DastBenchmarkStrategy.normalizeNumericId(issue.getCwe());
        if (!cwe.isEmpty()) {
            addKey(keyToRows, cweKey(endpoint, method, cwe), rowIndex);
        }
        String vulnerabilityKey = issue.getVulnerabilityKey();
        if (vulnerabilityKey != null && !vulnerabilityKey.trim().isEmpty()) {
            addKey(keyToRows, vulnerabilityKeyKey(endpoint, method, vulnerabilityKey), rowIndex);
        }
    }

    private static List<String> keysForFinding(Finding finding) {
        String endpoint = DastBenchmarkStrategy.normalizeUrl(finding.getUrl());
        String method = normalizeMethod(finding.getMethod());
        if (endpoint.isEmpty() || method.isEmpty()) {
            return new ArrayList<>();
        }
        List<String> keys = new ArrayList<>(3);
        String type = finding.getType();
        if (type != null && !type.trim().isEmpty()) {
            keys.add(typeKey(endpoint, method, type));
        }
        String cwe = DastBenchmarkStrategy.normalizeNumericId(finding.getCwe());
        if (!cwe.isEmpty()) {
            keys.add(cweKey(endpoint, method, cwe));
        }
        String vulnerabilityKey = finding.getVulnerabilityKey();
        if (vulnerabilityKey != null && !vulnerabilityKey.trim().isEmpty()) {
            keys.add(vulnerabilityKeyKey(endpoint, method, vulnerabilityKey));
        }
        return keys;
    }

    private static boolean hasEvidence(Finding finding) {
        return finding.getEvidence() != null && !finding.getEvidence().trim().isEmpty();
    }

    private static String findingSignature(Finding finding) {
        return String.join(
                "|",
                nullToEmpty(finding.getUrl()),
                nullToEmpty(finding.getMethod()),
                nullToEmpty(finding.getType()),
                nullToEmpty(finding.getCwe()),
                nullToEmpty(finding.getVulnerabilityKey()),
                nullToEmpty(finding.getEvidence()));
    }

    private static Finding toFinding(ExpectedIssue issue, String endpoint, String method) {
        return new Finding(
                endpoint,
                issue.getVulnerabilityType(),
                null,
                null,
                issue.getCwe(),
                null,
                method,
                issue.getVulnerabilityKey(),
                null,
                null,
                null);
    }

    private static void addKey(Map<String, Set<Integer>> map, String key, int rowIndex) {
        map.computeIfAbsent(key, k -> new LinkedHashSet<>()).add(rowIndex);
    }

    private static String typeKey(String endpoint, String method, String typeName) {
        return AXIS_TYPE
                + KEY_SEPARATOR
                + method
                + KEY_SEPARATOR
                + endpoint
                + KEY_SEPARATOR
                + typeName.trim().toUpperCase(Locale.ROOT);
    }

    private static String cweKey(String endpoint, String method, String cweDigits) {
        return AXIS_CWE
                + KEY_SEPARATOR
                + method
                + KEY_SEPARATOR
                + endpoint
                + KEY_SEPARATOR
                + cweDigits;
    }

    private static String vulnerabilityKeyKey(String endpoint, String method, String key) {
        return AXIS_KEY
                + KEY_SEPARATOR
                + method
                + KEY_SEPARATOR
                + endpoint
                + KEY_SEPARATOR
                + key.trim().toUpperCase(Locale.ROOT);
    }

    private static String normalizeMethod(String method) {
        return method == null ? "" : method.trim().toUpperCase(Locale.ROOT);
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
