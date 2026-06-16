package org.sasanlabs.beans;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.web.bind.annotation.RequestMethod;

/** Minimal black-box scope entry for external agent benchmarks. */
public class AgentScopeResponseBean {

    @JsonProperty("url")
    private final String url;

    @JsonProperty("method")
    private final RequestMethod method;

    public AgentScopeResponseBean(String url, RequestMethod method) {
        this.url = url;
        this.method = method;
    }

    public String getUrl() {
        return url;
    }

    public RequestMethod getMethod() {
        return method;
    }
}
