package org.sasanlabs.benchmark.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.sasanlabs.benchmark.model.ExpectedIssue;
import org.sasanlabs.internal.utility.annotations.AttackVector;
import org.sasanlabs.internal.utility.annotations.VulnerableAppRequestMapping;
import org.sasanlabs.internal.utility.annotations.VulnerableAppRestController;
import org.sasanlabs.vulnerability.types.VulnerabilityType;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

class AgentExpectedIssuesInventoryTest {

    @Test
    void agentCsvRowsMatchAnnotationDerivedScannerInventory() throws Exception {
        Set<InventoryRow> annotationRows = annotationRows();
        Set<InventoryRow> csvRows = csvRows();

        assertThat(csvRows).containsExactlyInAnyOrderElementsOf(annotationRows);
    }

    private static Set<InventoryRow> csvRows() throws Exception {
        Set<InventoryRow> rows = new LinkedHashSet<>();
        for (ExpectedIssue issue :
                new CsvExpectedIssuesProvider("scanner/sast/expectedIssues.csv")
                        .getExpectedIssues()) {
            if (!issue.isAgentMode()) {
                continue;
            }
            rows.add(
                    new InventoryRow(
                            issue.getCwe(),
                            issue.getVulnerabilityType(),
                            issue.getVulnerabilityKey(),
                            DastBenchmarkStrategy.normalizeUrl(issue.getEndpoint()),
                            issue.getMethod(),
                            issue.getVariant()));
        }
        return rows;
    }

    private static Set<InventoryRow> annotationRows() throws Exception {
        Set<InventoryRow> rows = new LinkedHashSet<>();
        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
        for (Resource resource :
                resolver.getResources(
                        "classpath*:org/sasanlabs/service/vulnerability/**/*.class")) {
            String className = toClassName(resource);
            if (className == null || className.contains("$")) {
                continue;
            }
            Class<?> clazz =
                    Class.forName(
                            className,
                            false,
                            AgentExpectedIssuesInventoryTest.class.getClassLoader());
            VulnerableAppRestController controller =
                    clazz.getAnnotation(VulnerableAppRestController.class);
            if (controller == null) {
                continue;
            }
            String vulnerabilityKey = controller.value();
            for (var method : clazz.getDeclaredMethods()) {
                VulnerableAppRequestMapping mapping =
                        method.getAnnotation(VulnerableAppRequestMapping.class);
                if (mapping == null) {
                    continue;
                }
                AttackVector[] attackVectors = method.getAnnotationsByType(AttackVector.class);
                if (attackVectors.length == 0) {
                    continue;
                }
                String endpoint =
                        DastBenchmarkStrategy.normalizeUrl(
                                "/" + vulnerabilityKey + "/" + mapping.value());
                for (AttackVector attackVector : attackVectors) {
                    for (VulnerabilityType type : attackVector.vulnerabilityExposed()) {
                        rows.add(
                                new InventoryRow(
                                        cwe(type),
                                        type.name(),
                                        vulnerabilityKey,
                                        endpoint,
                                        mapping.requestMethod().name(),
                                        mapping.variant().name()));
                    }
                }
            }
        }
        return rows;
    }

    private static String toClassName(Resource resource) throws Exception {
        String path = resource.getURL().getPath();
        int packageStart = path.indexOf("org/sasanlabs/service/vulnerability/");
        if (packageStart < 0 || !path.endsWith(".class")) {
            return null;
        }
        String classPath = path.substring(packageStart, path.length() - ".class".length());
        return classPath.replace('/', '.');
    }

    private static String cwe(VulnerabilityType type) {
        return type.getCweID() == null ? null : "CWE-" + type.getCweID();
    }

    private static final class InventoryRow {
        private final String cwe;
        private final String type;
        private final String vulnerabilityKey;
        private final String endpoint;
        private final String method;
        private final String variant;

        private InventoryRow(
                String cwe,
                String type,
                String vulnerabilityKey,
                String endpoint,
                String method,
                String variant) {
            this.cwe = cwe;
            this.type = type;
            this.vulnerabilityKey = vulnerabilityKey;
            this.endpoint = endpoint;
            this.method = method;
            this.variant = variant;
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof InventoryRow)) {
                return false;
            }
            InventoryRow that = (InventoryRow) other;
            return java.util.Objects.equals(cwe, that.cwe)
                    && java.util.Objects.equals(type, that.type)
                    && java.util.Objects.equals(vulnerabilityKey, that.vulnerabilityKey)
                    && java.util.Objects.equals(endpoint, that.endpoint)
                    && java.util.Objects.equals(method, that.method)
                    && java.util.Objects.equals(variant, that.variant);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(cwe, type, vulnerabilityKey, endpoint, method, variant);
        }

        @Override
        public String toString() {
            return "InventoryRow{"
                    + "cwe='"
                    + cwe
                    + '\''
                    + ", type='"
                    + type
                    + '\''
                    + ", vulnerabilityKey='"
                    + vulnerabilityKey
                    + '\''
                    + ", endpoint='"
                    + endpoint
                    + '\''
                    + ", method='"
                    + method
                    + '\''
                    + ", variant='"
                    + variant
                    + '\''
                    + '}';
        }
    }
}
