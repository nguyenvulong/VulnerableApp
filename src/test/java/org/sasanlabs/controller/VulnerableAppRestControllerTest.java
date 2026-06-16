package org.sasanlabs.controller;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.sasanlabs.beans.ScannerResponseBean;
import org.sasanlabs.service.IEndPointsInformationProvider;
import org.sasanlabs.vulnerability.types.VulnerabilityType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMethod;

@ExtendWith(MockitoExtension.class)
class VulnerableAppRestControllerTest {

    @Mock private IEndPointsInformationProvider endpointsProvider;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc =
                MockMvcBuilders.standaloneSetup(new VulnerableAppRestController(endpointsProvider))
                        .build();
    }

    @Test
    void agentScopeReturnsOnlyUrlsAndMethods() throws Exception {
        when(endpointsProvider.getScannerRelatedEndPointInformation(anyString()))
                .thenReturn(
                        Arrays.asList(
                                new ScannerResponseBean(
                                        "http://localhost/VulnerableApp/XSS/LEVEL_1",
                                        "UNSECURE",
                                        RequestMethod.GET,
                                        Collections.singletonList(VulnerabilityType.REFLECTED_XSS)),
                                new ScannerResponseBean(
                                        "http://localhost/VulnerableApp/XSS/LEVEL_1",
                                        "UNSECURE",
                                        RequestMethod.GET,
                                        Collections.singletonList(VulnerabilityType.REFLECTED_XSS)),
                                new ScannerResponseBean(
                                        "http://localhost/VulnerableApp/Command/LEVEL_1",
                                        "UNSECURE",
                                        RequestMethod.POST,
                                        Collections.singletonList(
                                                VulnerabilityType.COMMAND_INJECTION))));

        mockMvc.perform(get("/scanner/agent/scope"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[0].url").value("http://localhost/VulnerableApp/XSS/LEVEL_1"))
                .andExpect(jsonPath("$[0].method").value("GET"))
                .andExpect(jsonPath("$[0].variant").doesNotExist())
                .andExpect(jsonPath("$[0].vulnerabilityTypes").doesNotExist())
                .andExpect(jsonPath("$[0].cwe").doesNotExist())
                .andExpect(jsonPath("$[0].type").doesNotExist())
                .andExpect(
                        jsonPath("$[1].url")
                                .value("http://localhost/VulnerableApp/Command/LEVEL_1"))
                .andExpect(jsonPath("$[1].method").value("POST"))
                .andExpect(jsonPath("$[2]").doesNotExist());
    }
}
