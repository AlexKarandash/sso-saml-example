package com.subbotin.saml.services;

import com.subbotin.saml.exceptions.SamlAuthRedirectWasUnsuccessfulException;
import com.subbotin.saml.exceptions.SamlResponseIsNotCorrectException;
import com.subbotin.saml.exceptions.ValidateSignatureForResponseWasUnsuccessfulException;
import com.subbotin.saml.saml.SamlRequest;
import com.subbotin.saml.saml.SamlResponse;
import com.subbotin.saml.saml.SamlSettings;
import com.subbotin.saml.utils.FileUtils;
import com.subbotin.saml.utils.SamlExceptionText;
import com.subbotin.saml.utils.SamlSystemUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.cxf.common.util.CompressionUtils;
import org.apache.http.client.utils.URIBuilder;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.validation.Validator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class SamlServiceImpl implements SamlService {
    static Logger logger = LoggerFactory.getLogger(SamlServiceImpl.class);
    static SamlSystemService samlSystemService = new SamlSystemServiceImpl();

    @Override
    public SamlRequest createSamlRequest(String acsUrl) {
        try {
            AuthnRequest authnRequest = samlSystemService.createAuthnRequest(acsUrl, SamlSystemUtils.generateId(), DateTime.now(), SamlSystemUtils.ISSUER_NAME);
            String request = samlSystemService.convertXmlObjectToString(authnRequest);
            String requestBase64 = Base64.encodeBase64String(CompressionUtils.deflate(getBytesWithCatch(request, SamlExceptionText.PROBLEM_DEFLATE_AND_ENCODE_REQUEST_TO_BASE64)));
            return new SamlRequest(authnRequest, requestBase64);
        } catch (SAMLException e) {
            throw new SamlAuthRedirectWasUnsuccessfulException(e);
        }
    }

    @Override
    public URI getUriRequest(String samlEndpoint, String authRequest) {
        try {
            URIBuilder uriBuilder = new URIBuilder(samlEndpoint);
            uriBuilder.setCharset(StandardCharsets.UTF_8);
            uriBuilder.addParameter("SAMLRequest", authRequest);
            return uriBuilder.build();
        } catch (URISyntaxException e) {
            throw new SamlAuthRedirectWasUnsuccessfulException(e);
        }
    }

    @Override
    public SamlResponse createSamlResponse(String samlResponse) {
        try {
            String xml = new String(Base64.decodeBase64(getBytesWithCatch(samlResponse, SamlExceptionText.PROBLEM_DECODE_RESPONSE_FROM_BASE64)));
            XMLObject xmlObject = samlSystemService.convertStringToXmlObject(xml);
            Response response = samlSystemService.getResponseAndValidateSchema(xmlObject);
            samlSystemService.checkStatusCode(response);

            Assertion assertion = samlSystemService.getCheckedAssertion(response);
            samlSystemService.checkConditions(assertion);

            String subjectNameId = samlSystemService.getSubjectNameId(assertion);
            Map<String, List<String>> attributeValues = samlSystemService.getAttributeValues(assertion);

            return new SamlResponse(response, assertion, attributeValues, subjectNameId);
        } catch (SAMLException e) {
            throw new SamlResponseIsNotCorrectException(e);
        }
    }

    @Override
    public void checkSignature(SamlResponse samlResponse, String certificate) {
        try {
            Validator<Signature> signatureValidator = samlSystemService.getValidator(certificate);
            samlSystemService.validateOptionalSignature(signatureValidator, samlResponse.getResponse());
            samlSystemService.validateMandatorySignature(signatureValidator, samlResponse.getAssertion());
        } catch (SAMLException e) {
            throw new ValidateSignatureForResponseWasUnsuccessfulException(e);
        }
    }

    @Override
    public String getUserName(SamlResponse samlResponse) {
        Map<String, List<String>> attributeValues = samlResponse.getAttributeValues();
        String firstName = getSingleValue("FirstName", attributeValues);
        String lastName = getSingleValue("LastName", attributeValues);
        return StringUtils.trim(firstName + " " + lastName);
    }

    private String getSingleValue(String attributeName, Map<String, List<String>> attributeValues) {
        return attributeValues.getOrDefault(attributeName, Collections.emptyList()).stream().findFirst().orElse(StringUtils.EMPTY);
    }

    private byte[] getBytesWithCatch(String value, String textError) throws SAMLException {
        try {
            return value.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            logger.error(e.getMessage(), e);
            throw new SAMLException(textError, e);
        }
    }

    private String getDomain(String email) {
        return email.substring(email.lastIndexOf("@") + 1);
    }

    @Override
    @Nullable
    public SamlSettings getSamlSettings(String email) {
        String domain = getDomain(email);
        String propertiesFileName = "src/main/resources/" + domain + ".properties";
        try {
            String samlEndpoint = FileUtils.getProperty(propertiesFileName, "samlEndpoint");
            String x509Certificate = FileUtils.getProperty(propertiesFileName, "x509Certificate");
            return new SamlSettings(samlEndpoint, x509Certificate);
        } catch (IOException e) {
            return null;
        }
    }
}
