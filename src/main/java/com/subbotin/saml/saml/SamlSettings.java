package com.subbotin.saml.saml;

public class SamlSettings {
    private String samlEndpoint;
    private String x509Certificate;

    public SamlSettings(String samlEndpoint, String x509Certificate) {
        this.samlEndpoint = samlEndpoint;
        this.x509Certificate = x509Certificate;
    }

    public String getSamlEndpoint() {
        return samlEndpoint;
    }

    public String getX509Certificate() {
        return x509Certificate;
    }
}
