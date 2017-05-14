package com.subbotin.saml.services;

import com.subbotin.saml.saml.SamlRequest;
import com.subbotin.saml.saml.SamlResponse;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.validation.Validator;
import org.slf4j.Logger;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;

@Test
public class SamlServiceImplTest {
    private SamlSystemService samlSystemService;
    private SamlServiceImpl samlServiceSpy;

    @BeforeMethod
    public void setUp() throws Exception {
        SamlServiceImpl.logger = mock(Logger.class, RETURNS_DEEP_STUBS);
        samlSystemService = mock(SamlSystemService.class);
        SamlServiceImpl.samlSystemService = samlSystemService;
        samlServiceSpy = spy(SamlServiceImpl.class);
    }

    public void shouldCallAllInnerMethodWhenCreateRequest() throws SAMLException {
        AuthnRequest authnRequest = mock(AuthnRequest.class);
        doReturn(authnRequest).when(samlSystemService).createAuthnRequest(anyString(), anyString(), any(), anyString());
        doReturn("1").when(samlSystemService).convertXmlObjectToString(authnRequest);

        SamlRequest samlRequest = samlServiceSpy.createSamlRequest("https://realtimeboard.com/saml/acs");

        verify(samlSystemService).createAuthnRequest(eq("https://realtimeboard.com/saml/acs"), anyString(), any(), anyString());
        verify(samlSystemService).convertXmlObjectToString(eq(authnRequest));
        Assert.assertNotNull(samlRequest);
        Assert.assertEquals(samlRequest.getAuthnRequest(), authnRequest);
        Assert.assertTrue(!samlRequest.getRequestBase64().isEmpty());
    }

    public void shouldCallAllInnerMethodWhenCreateResponse() throws SAMLException {
        XMLObject xmlObject = mock(XMLObject.class);
        doReturn(xmlObject).when(samlSystemService).convertStringToXmlObject(anyString());
        Response response = mock(Response.class);
        doReturn(response).when(samlSystemService).getResponseAndValidateSchema(xmlObject);
        doNothing().when(samlSystemService).checkStatusCode(response);
        Assertion assertion = mock(Assertion.class);
        doReturn(assertion).when(samlSystemService).getCheckedAssertion(response);
        doNothing().when(samlSystemService).checkConditions(assertion);
        String subjectNameId = "testSubject";
        doReturn(subjectNameId).when(samlSystemService).getSubjectNameId(assertion);
        Map attributeValues = Collections.singletonMap("testKey", Collections.singletonList("testValue"));
        doReturn(attributeValues).when(samlSystemService).getAttributeValues(assertion);

        SamlResponse samlResponse = samlServiceSpy.createSamlResponse("test");

        verify(samlSystemService).convertStringToXmlObject(anyString());
        verify(samlSystemService).getResponseAndValidateSchema(eq(xmlObject));
        verify(samlSystemService).checkStatusCode(eq(response));
        verify(samlSystemService).getCheckedAssertion(eq(response));
        verify(samlSystemService).checkConditions(eq(assertion));
        verify(samlSystemService).getSubjectNameId(eq(assertion));
        verify(samlSystemService).getAttributeValues(eq(assertion));
        Assert.assertNotNull(samlResponse);
        Assert.assertEquals(samlResponse.getResponse(), response);
        Assert.assertEquals(samlResponse.getAssertion(), assertion);
        Assert.assertEquals(samlResponse.getSubjectNameId(), subjectNameId);
        Assert.assertEquals(samlResponse.getAttributeValues(), attributeValues);
    }

    @SuppressWarnings("unchecked")
    public void shouldCallAllInnerMethodWhenCheckSignature() throws SAMLException {
        SamlResponse samlResponse = mock(SamlResponse.class);
        Response response = mock(Response.class);
        doReturn(response).when(samlResponse).getResponse();
        Assertion assertion = mock(Assertion.class);
        doReturn(assertion).when(samlResponse).getAssertion();
        String certificate = "test";
        Validator<Signature> signatureValidator = mock(Validator.class);
        doReturn(signatureValidator).when(samlSystemService).getValidator(certificate);
        doNothing().when(samlSystemService).validateOptionalSignature(eq(signatureValidator), any());
        doNothing().when(samlSystemService).validateMandatorySignature(eq(signatureValidator), any());

        samlServiceSpy.checkSignature(samlResponse, certificate);

        verify(samlSystemService).getValidator(eq(certificate));
        verify(samlSystemService).validateOptionalSignature(eq(signatureValidator), eq(response));
        verify(samlSystemService).validateMandatorySignature(eq(signatureValidator), eq(assertion));
    }

    public void shouldGetUserName() {
        SamlResponse samlResponse = mock(SamlResponse.class);
        Map<String, List<String>> attributeValues = new HashMap<>();
        attributeValues.put("FirstName", Collections.singletonList("first"));
        attributeValues.put("LastName", Collections.singletonList("last"));
        doReturn(attributeValues).when(samlResponse).getAttributeValues();

        String userName = samlServiceSpy.getUserName(samlResponse);

        Assert.assertEquals(userName, "first last");
    }

    public void shouldGetUriRequest() {
        URI uri = samlServiceSpy.getUriRequest("https://onelogin.com/saml", "1");

        Assert.assertEquals(uri.toString(), "https://onelogin.com/saml?SAMLRequest=1");
    }
}