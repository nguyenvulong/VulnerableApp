package org.sasanlabs.benchmark.service;

import java.io.IOException;
import org.sasanlabs.benchmark.model.BenchmarkResult;
import org.sasanlabs.benchmark.model.ScanType;
import org.sasanlabs.benchmark.model.ScannerFindings;
import org.springframework.stereotype.Service;

/**
 * Entry point for the scanner-benchmark API. Dispatches to a {@link BenchmarkStrategy}
 * implementation based on the {@link ScanType} of the incoming request.
 */
@Service
public class BenchmarkService {

    private final DastBenchmarkStrategy dastStrategy;
    private final SastBenchmarkStrategy sastStrategy;
    private final AgentBenchmarkStrategy agentStrategy;

    public BenchmarkService(
            DastBenchmarkStrategy dastStrategy,
            SastBenchmarkStrategy sastStrategy,
            AgentBenchmarkStrategy agentStrategy) {
        this.dastStrategy = dastStrategy;
        this.sastStrategy = sastStrategy;
        this.agentStrategy = agentStrategy;
    }

    public BenchmarkResult compare(ScannerFindings input) throws IOException {
        ScanType scanType = input.getScanType() != null ? input.getScanType() : ScanType.DAST;
        switch (scanType) {
            case DAST:
                return dastStrategy.compare(input);
            case SAST:
                return sastStrategy.compare(input);
            case AGENT:
                return agentStrategy.compare(input);
            default:
                throw new IllegalArgumentException("Unsupported scan type: " + scanType);
        }
    }
}
