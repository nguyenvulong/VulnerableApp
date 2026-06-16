package org.sasanlabs.benchmark.service;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.sasanlabs.benchmark.model.ExpectedIssue;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Loads SAST ground truth from a CSV file with header columns {@code CWE}, {@code Vulnerability
 * Type}, {@code File}, {@code Line}, {@code Number of Sources}. Expanded benchmark CSVs may also
 * include {@code Issue Id}, {@code Vulnerability Key}, {@code Endpoint}, {@code Method}, {@code
 * Variant}, and {@code Mode}. The default path points at {@code scanner/sast/expectedIssues.csv} in
 * the project root; override via the {@code benchmark.sast.ground-truth.path} property.
 *
 * <p>Rows that fail to parse (missing columns, non-integer line / sources) are logged and skipped —
 * one bad row should not abort an entire benchmark run.
 */
@Component
public class CsvExpectedIssuesProvider implements IExpectedIssuesProvider {

    private static final Logger LOGGER = LogManager.getLogger(CsvExpectedIssuesProvider.class);

    private static final String COL_CWE = "CWE";
    private static final String COL_TYPE = "Vulnerability Type";
    private static final String COL_FILE = "File";
    private static final String COL_LINE = "Line";
    private static final String COL_SOURCES = "Number of Sources";
    private static final String COL_ISSUE_ID = "Issue Id";
    private static final String COL_VULNERABILITY_KEY = "Vulnerability Key";
    private static final String COL_ENDPOINT = "Endpoint";
    private static final String COL_METHOD = "Method";
    private static final String COL_VARIANT = "Variant";
    private static final String COL_MODE = "Mode";
    private static final String MODE_SAST = "SAST";
    private static final String MODE_AGENT = "AGENT";

    private static final CSVFormat FORMAT =
            CSVFormat.DEFAULT
                    .builder()
                    .setHeader()
                    .setSkipHeaderRecord(true)
                    .setIgnoreEmptyLines(true)
                    .setTrim(true)
                    .build();

    private final String csvPath;

    public CsvExpectedIssuesProvider(
            @Value("${benchmark.sast.ground-truth.path:scanner/sast/expectedIssues.csv}")
                    String csvPath) {
        this.csvPath = csvPath;
    }

    @Override
    public List<ExpectedIssue> getExpectedIssues() throws IOException {
        Path path = Paths.get(csvPath);
        List<ExpectedIssue> issues = new ArrayList<>();
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8);
                CSVParser parser = FORMAT.parse(reader)) {
            for (CSVRecord row : parser) {
                ExpectedIssue issue = parseRow(row);
                if (issue != null) {
                    issues.add(issue);
                }
            }
        }
        LOGGER.info("Loaded {} expected SAST issues from {}", issues.size(), csvPath);
        return issues;
    }

    private ExpectedIssue parseRow(CSVRecord row) {
        if (!isSet(row, COL_CWE) || !isSet(row, COL_TYPE)) {
            LOGGER.warn(
                    "Skipping malformed SAST CSV row at line {} of {}: missing required columns",
                    row.getRecordNumber(),
                    csvPath);
            return null;
        }
        String mode = defaultIfBlank(getOptional(row, COL_MODE), MODE_SAST);
        if (MODE_AGENT.equalsIgnoreCase(mode)) {
            return parseAgentRow(row, mode);
        }
        return parseSastRow(row, mode);
    }

    private ExpectedIssue parseSastRow(CSVRecord row, String mode) {
        if (!isSet(row, COL_FILE) || !isSet(row, COL_LINE) || !isSet(row, COL_SOURCES)) {
            LOGGER.warn(
                    "Skipping malformed SAST CSV row at line {} of {}: missing required columns",
                    row.getRecordNumber(),
                    csvPath);
            return null;
        }
        try {
            return new ExpectedIssue(
                    getOptional(row, COL_CWE),
                    getOptional(row, COL_TYPE),
                    getOptional(row, COL_FILE),
                    parseInteger(getOptional(row, COL_LINE)),
                    parseInteger(getOptional(row, COL_SOURCES)),
                    getOptional(row, COL_ISSUE_ID),
                    getOptional(row, COL_VULNERABILITY_KEY),
                    getOptional(row, COL_ENDPOINT),
                    getOptional(row, COL_METHOD),
                    getOptional(row, COL_VARIANT),
                    mode);
        } catch (NumberFormatException nfe) {
            LOGGER.warn(
                    "Skipping SAST CSV row at line {} of {}: non-integer line or sources column"
                            + " ({})",
                    row.getRecordNumber(),
                    csvPath,
                    nfe.getMessage());
            return null;
        }
    }

    private ExpectedIssue parseAgentRow(CSVRecord row, String mode) {
        if (!isSet(row, COL_ENDPOINT) || !isSet(row, COL_METHOD) || !isSet(row, COL_VARIANT)) {
            LOGGER.warn(
                    "Skipping malformed AGENT CSV row at line {} of {}: missing required columns",
                    row.getRecordNumber(),
                    csvPath);
            return null;
        }
        try {
            return new ExpectedIssue(
                    getOptional(row, COL_CWE),
                    getOptional(row, COL_TYPE),
                    getOptional(row, COL_FILE),
                    parseOptionalInteger(row, COL_LINE),
                    parseOptionalInteger(row, COL_SOURCES),
                    getOptional(row, COL_ISSUE_ID),
                    getOptional(row, COL_VULNERABILITY_KEY),
                    getOptional(row, COL_ENDPOINT),
                    getOptional(row, COL_METHOD),
                    getOptional(row, COL_VARIANT),
                    mode);
        } catch (NumberFormatException nfe) {
            LOGGER.warn(
                    "Skipping AGENT CSV row at line {} of {}: non-integer line or sources column"
                            + " ({})",
                    row.getRecordNumber(),
                    csvPath,
                    nfe.getMessage());
            return null;
        }
    }

    private static boolean isSet(CSVRecord row, String column) {
        return row.isMapped(column) && row.isSet(column) && !row.get(column).trim().isEmpty();
    }

    private static String getOptional(CSVRecord row, String column) {
        if (!row.isMapped(column) || !row.isSet(column)) {
            return null;
        }
        String value = row.get(column);
        return value == null || value.trim().isEmpty() ? null : value.trim();
    }

    private static String defaultIfBlank(String value, String defaultValue) {
        return value == null || value.trim().isEmpty() ? defaultValue : value.trim();
    }

    private static Integer parseOptionalInteger(CSVRecord row, String column) {
        String value = getOptional(row, column);
        return value == null ? null : parseInteger(value);
    }

    private static Integer parseInteger(String value) {
        return Integer.valueOf(value);
    }
}
