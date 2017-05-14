package com.subbotin.saml.services;

import com.subbotin.saml.saml.SamlRequest;
import com.subbotin.saml.saml.SamlResponse;
import com.subbotin.saml.saml.SamlSettings;

import javax.annotation.Nullable;
import java.net.URI;

public interface SamlService {
    SamlRequest createSamlRequest(String acsUrl);

    URI getUriRequest(String samlEndpoint, String authRequest);

    SamlResponse createSamlResponse(String samlResponse);

    void checkSignature(SamlResponse samlResponse, String certificate);

    String getUserName(SamlResponse samlResponse);

    @Nullable
    SamlSettings getSamlSettings(String email);
}
