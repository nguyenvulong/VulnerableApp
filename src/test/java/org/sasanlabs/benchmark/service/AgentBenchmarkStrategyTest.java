package org.sasanlabs.benchmark.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.sasanlabs.benchmark.model.BenchmarkResult;
import org.sasanlabs.benchmark.model.ExpectedIssue;
import org.sasanlabs.benchmark.model.Finding;
import org.sasanlabs.benchmark.model.ScanType;
import org.sasanlabs.benchmark.model.ScannerFindings;

@ExtendWith(MockitoExtension.class)
class AgentBenchmarkStrategyTest {

    @Mock private IExpectedIssuesProvider provider;

    private AgentBenchmarkStrategy strategy;

    @BeforeEach
    void setUp() {
        strategy = new AgentBenchmarkStrategy(provider);
    }

    @Test
    void matchesByNormalizedEndpointAndAnyTaxonomyAxis() throws Exception {
        when(provider.getExpectedIssues())
                .thenReturn(
                        Arrays.asList(
                                agentIssue(
                                        "agent-1",
                                        "CWE-89",
                                        "BLIND_SQL_INJECTION",
                                        "BlindSQLInjectionVulnerability",
                                        "/BlindSQLInjectionVulnerability/LEVEL_1",
                                        "GET",
                                        "UNSECURE"),
                                agentIssue(
                                        "agent-2",
                                        "CWE-79",
                                        "REFLECTED_XSS",
                                        "XSSWithHtmlTagInjection",
                                        "/XSSWithHtmlTagInjection/LEVEL_1",
                                        "GET",
                                        "UNSECURE"),
                                agentIssue(
                                        "agent-3",
                                        "CWE-77",
                                        "COMMAND_INJECTION",
                                        "CommandInjection",
                                        "/CommandInjection/LEVEL_1",
                                        "POST",
                                        "UNSECURE")));

        BenchmarkResult result =
                strategy.compare(
                        input(
                                finding(
                                        "http://localhost:9090/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_1?x=1",
                                        "GET",
                                        null,
                                        "CWE-89",
                                        null,
                                        "boolean delay observed"),
                                finding(
                                        "/XSSWithHtmlTagInjection/LEVEL_1/",
                                        "get",
                                        "reflected_xss",
                                        null,
                                        null,
                                        "script reflected"),
                                finding(
                                        "/CommandInjection/LEVEL_1",
                                        "POST",
                                        null,
                                        null,
                                        "CommandInjection",
                                        "command output returned")));

        assertThat(result.getCoverage()).isEqualTo(100.0);
        assertThat(result.getDetected()).isEqualTo(3);
        assertThat(result.getUnmatched()).isZero();
    }

    @Test
    void secureEndpointReport_isUnmatched() throws Exception {
        when(provider.getExpectedIssues())
                .thenReturn(
                        Arrays.asList(
                                agentIssue(
                                        "agent-1",
                                        "CWE-79",
                                        "REFLECTED_XSS",
                                        "XSSWithHtmlTagInjection",
                                        "/XSSWithHtmlTagInjection/LEVEL_1",
                                        "GET",
                                        "UNSECURE"),
                                agentIssue(
                                        "agent-2",
                                        "CWE-79",
                                        "REFLECTED_XSS",
                                        "XSSWithHtmlTagInjection",
                                        "/XSSWithHtmlTagInjection/LEVEL_4",
                                        "GET",
                                        "SECURE")));

        BenchmarkResult result =
                strategy.compare(
                        input(
                                finding(
                                        "/XSSWithHtmlTagInjection/LEVEL_4",
                                        "GET",
                                        null,
                                        "CWE-79",
                                        null,
                                        "reported a secure level")));

        assertThat(result.getTotalExpected()).isEqualTo(1);
        assertThat(result.getDetected()).isZero();
        assertThat(result.getUnmatched()).isEqualTo(1);
        assertThat(result.getMissedItems())
                .extracting(Finding::getUrl, Finding::getMethod, Finding::getCwe)
                .containsExactly(tuple("/XSSWithHtmlTagInjection/LEVEL_1", "GET", "CWE-79"));
    }

    @Test
    void findingWithoutEvidence_isUnmatched() throws Exception {
        when(provider.getExpectedIssues())
                .thenReturn(
                        Collections.singletonList(
                                agentIssue(
                                        "agent-1",
                                        "CWE-89",
                                        "BLIND_SQL_INJECTION",
                                        "BlindSQLInjectionVulnerability",
                                        "/BlindSQLInjectionVulnerability/LEVEL_1",
                                        "GET",
                                        "UNSECURE")));

        BenchmarkResult result =
                strategy.compare(
                        input(
                                finding(
                                        "/BlindSQLInjectionVulnerability/LEVEL_1",
                                        "GET",
                                        null,
                                        "CWE-89",
                                        null,
                                        "   ")));

        assertThat(result.getDetected()).isZero();
        assertThat(result.getMissed()).isEqualTo(1);
        assertThat(result.getUnmatched()).isEqualTo(1);
    }

    @Test
    void methodMustMatch() throws Exception {
        when(provider.getExpectedIssues())
                .thenReturn(
                        Collections.singletonList(
                                agentIssue(
                                        "agent-1",
                                        "CWE-77",
                                        "COMMAND_INJECTION",
                                        "CommandInjection",
                                        "/CommandInjection/LEVEL_1",
                                        "POST",
                                        "UNSECURE")));

        BenchmarkResult result =
                strategy.compare(
                        input(
                                finding(
                                        "/CommandInjection/LEVEL_1",
                                        "GET",
                                        null,
                                        "CWE-77",
                                        null,
                                        "command output")));

        assertThat(result.getDetected()).isZero();
        assertThat(result.getUnmatched()).isEqualTo(1);
    }

    private static ScannerFindings input(Finding... findings) {
        return new ScannerFindings("Agent", ScanType.AGENT, Arrays.asList(findings));
    }

    private static Finding finding(
            String url,
            String method,
            String type,
            String cwe,
            String vulnerabilityKey,
            String evidence) {
        return new Finding(
                url, type, null, null, cwe, null, method, vulnerabilityKey, evidence, null, null);
    }

    private static ExpectedIssue agentIssue(
            String issueId,
            String cwe,
            String type,
            String vulnerabilityKey,
            String endpoint,
            String method,
            String variant) {
        return new ExpectedIssue(
                cwe,
                type,
                null,
                null,
                null,
                issueId,
                vulnerabilityKey,
                endpoint,
                method,
                variant,
                "AGENT");
    }
}
