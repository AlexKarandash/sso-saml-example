package com.subbotin.saml.saml;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;

import java.util.List;
import java.util.Map;

public class SamlResponse {
    private Response response;
    private Assertion assertion;
    private Map<String, List<String>> attributeValues;
    private String subjectNameId;

    public SamlResponse(Response response, Assertion assertion, Map<String, List<String>> attributeValues, String subjectNameId) {
        this.response = response;
        this.assertion = assertion;
        this.attributeValues = attributeValues;
        this.subjectNameId = subjectNameId;
    }

    public Response getResponse() {
        return response;
    }

    public Assertion getAssertion() {
        return assertion;
    }

    public Map<String, List<String>> getAttributeValues() {
        return attributeValues;
    }

    public String getSubjectNameId() {
        return subjectNameId;
    }
}
