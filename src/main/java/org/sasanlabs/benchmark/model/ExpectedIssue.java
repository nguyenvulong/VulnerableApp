package org.sasanlabs.benchmark.model;

/**
 * One row of SAST ground truth — a known vulnerability site in VulnerableApp's source tree, as
 * declared by {@code scanner/sast/expectedIssues.csv}. Used by the SAST benchmark strategy to
 * compare scanner findings against expected issues.
 */
public class ExpectedIssue {

    private final String cwe;
    private final String vulnerabilityType;
    private final String filePath;
    private final Integer line;
    private final Integer numberOfSources;
    private final String issueId;
    private final String vulnerabilityKey;
    private final String endpoint;
    private final String method;
    private final String variant;
    private final String mode;

    public ExpectedIssue(
            String cwe, String vulnerabilityType, String filePath, int line, int numberOfSources) {
        this(
                cwe,
                vulnerabilityType,
                filePath,
                line,
                numberOfSources,
                null,
                null,
                null,
                null,
                null,
                "SAST");
    }

    public ExpectedIssue(
            String cwe,
            String vulnerabilityType,
            String filePath,
            Integer line,
            Integer numberOfSources,
            String issueId,
            String vulnerabilityKey,
            String endpoint,
            String method,
            String variant,
            String mode) {
        this.cwe = cwe;
        this.vulnerabilityType = vulnerabilityType;
        this.filePath = filePath;
        this.line = line;
        this.numberOfSources = numberOfSources;
        this.issueId = issueId;
        this.vulnerabilityKey = vulnerabilityKey;
        this.endpoint = endpoint;
        this.method = method;
        this.variant = variant;
        this.mode = mode;
    }

    public String getCwe() {
        return cwe;
    }

    public String getVulnerabilityType() {
        return vulnerabilityType;
    }

    public String getFilePath() {
        return filePath;
    }

    public Integer getLine() {
        return line;
    }

    public Integer getNumberOfSources() {
        return numberOfSources;
    }

    public String getIssueId() {
        return issueId;
    }

    public String getVulnerabilityKey() {
        return vulnerabilityKey;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public String getMethod() {
        return method;
    }

    public String getVariant() {
        return variant;
    }

    public String getMode() {
        return mode;
    }

    public boolean isSastMode() {
        return mode == null || mode.trim().isEmpty() || "SAST".equalsIgnoreCase(mode.trim());
    }

    public boolean isAgentMode() {
        return "AGENT".equalsIgnoreCase(mode);
    }
}
