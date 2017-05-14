package com.subbotin.saml.saml;

import org.opensaml.saml2.core.AuthnRequest;

public class SamlRequest {
    private AuthnRequest authnRequest;
    private String requestBase64;

    public SamlRequest(AuthnRequest authnRequest, String requestBase64) {
        this.authnRequest = authnRequest;
        this.requestBase64 = requestBase64;
    }

    public AuthnRequest getAuthnRequest() {
        return authnRequest;
    }

    public String getRequestBase64() {
        return requestBase64;
    }
}
