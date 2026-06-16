package org.sasanlabs.benchmark.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A single scanner finding. DAST findings populate {@code url} + {@code type} (and optionally
 * {@code method} / {@code cwe} / {@code wascId} for taxonomy-tolerant matching); SAST findings
 * populate {@code filePath} + {@code line} + {@code type} (and optionally {@code cwe}); AGENT
 * findings populate {@code url} + {@code method} + evidence and one taxonomy axis. Unused fields
 * are omitted from the serialised output.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Finding {

    @JsonProperty("url")
    private String url;

    @JsonProperty("type")
    private String type;

    @JsonProperty("filePath")
    private String filePath;

    @JsonProperty("line")
    private Integer line;

    @JsonProperty("cwe")
    private String cwe;

    @JsonProperty("wascId")
    private String wascId;

    @JsonProperty("method")
    private String method;

    @JsonProperty("vulnerabilityKey")
    private String vulnerabilityKey;

    @JsonProperty("evidence")
    private String evidence;

    @JsonProperty("request")
    private String request;

    @JsonProperty("responseSnippet")
    private String responseSnippet;

    @JsonCreator
    public Finding(
            @JsonProperty("url") String url,
            @JsonProperty("type") String type,
            @JsonProperty("filePath") String filePath,
            @JsonProperty("line") Integer line,
            @JsonProperty("cwe") String cwe,
            @JsonProperty("wascId") String wascId,
            @JsonProperty("method") String method,
            @JsonProperty("vulnerabilityKey") String vulnerabilityKey,
            @JsonProperty("evidence") String evidence,
            @JsonProperty("request") String request,
            @JsonProperty("responseSnippet") String responseSnippet) {
        this.url = url;
        this.type = type;
        this.filePath = filePath;
        this.line = line;
        this.cwe = cwe;
        this.wascId = wascId;
        this.method = method;
        this.vulnerabilityKey = vulnerabilityKey;
        this.evidence = evidence;
        this.request = request;
        this.responseSnippet = responseSnippet;
    }

    public Finding(
            String url,
            String type,
            String filePath,
            Integer line,
            String cwe,
            String wascId,
            String method) {
        this(url, type, filePath, line, cwe, wascId, method, null, null, null, null);
    }

    public Finding(
            String url, String type, String filePath, Integer line, String cwe, String wascId) {
        this(url, type, filePath, line, cwe, wascId, null);
    }

    public Finding(String url, String type, String filePath, Integer line, String cwe) {
        this(url, type, filePath, line, cwe, null, null);
    }

    public Finding(String url, String type) {
        this(url, type, null, null, null, null, null);
    }

    public String getUrl() {
        return url;
    }

    public String getType() {
        return type;
    }

    public String getFilePath() {
        return filePath;
    }

    public Integer getLine() {
        return line;
    }

    public String getCwe() {
        return cwe;
    }

    public String getWascId() {
        return wascId;
    }

    public String getMethod() {
        return method;
    }

    public String getVulnerabilityKey() {
        return vulnerabilityKey;
    }

    public String getEvidence() {
        return evidence;
    }

    public String getRequest() {
        return request;
    }

    public String getResponseSnippet() {
        return responseSnippet;
    }
}
