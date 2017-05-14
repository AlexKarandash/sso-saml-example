package com.subbotin.saml.services;

import com.subbotin.saml.utils.SamlExceptionText;
import com.subbotin.saml.utils.SamlSystemUtils;
import org.apache.cxf.helpers.IOUtils;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.Validator;
import org.slf4j.Logger;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Map;

import static org.mockito.Matchers.any;

@Test
public class SamlSystemServiceImplTest {
    private SamlSystemService samlSystemService = new SamlSystemServiceImpl();
    private DateTime ISSUE_INSTANT = DateTime.now().withZone(DateTimeZone.UTC);

    @BeforeMethod
    public void setUp() {
        SamlSystemServiceImpl.logger = mock(Logger.class, RETURNS_DEEP_STUBS);
        SamlSystemUtils.logger = mock(Logger.class, RETURNS_DEEP_STUBS);
        SamlSystemUtils.init();
    }

    public void testCreateAuthnRequest() throws Exception {
        String acsUrl = "https://realtimeboard.com/sso/acs";
        String issuerName = "https://realtimeboard.com";
        String requestId = "asafdsfsdfsdfsdfsdf";

        AuthnRequest authnRequest = samlSystemService.createAuthnRequest(acsUrl, requestId, ISSUE_INSTANT, issuerName);

        Assert.assertEquals(authnRequest.getAssertionConsumerServiceURL(), acsUrl);
        Assert.assertEquals(authnRequest.getID(), requestId);
        Assert.assertEquals(authnRequest.getIssueInstant(), ISSUE_INSTANT);
        Assert.assertEquals(authnRequest.getVersion(), SAMLVersion.VERSION_20);
        Assert.assertEquals(authnRequest.getProtocolBinding(), SAMLConstants.SAML2_POST_BINDING_URI);
        Assert.assertEquals(authnRequest.getIssuer().getValue(), issuerName);
        Assert.assertEquals(authnRequest.getNameIDPolicy().getFormat(), NameIDType.EMAIL);
        Assert.assertEquals(authnRequest.getRequestedAuthnContext().getComparison(), AuthnContextComparisonTypeEnumeration.EXACT);
        Assert.assertEquals(authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().get(0).getAuthnContextClassRef(), AuthnContext.PPT_AUTHN_CTX);
    }

    public void shouldCreateAuthnRequestWhenBuildAuthnRequest() throws Exception {
        SAMLObject object = samlSystemService.build(AuthnRequest.DEFAULT_ELEMENT_NAME);

        Assert.assertTrue(object instanceof AuthnRequest);
    }

    public void shouldCreateNotAuthnRequestWhenBuildIssuer() throws Exception {
        SAMLObject object = samlSystemService.build(Issuer.DEFAULT_ELEMENT_NAME);

        Assert.assertFalse(object instanceof AuthnRequest);
    }

    @Test(expectedExceptions = SAMLException.class, expectedExceptionsMessageRegExp = SamlExceptionText.XMLOBJECT_NOT_CAST_TO_RESPONSE)
    public void shouldThrowExceptionNotCast() throws SAMLException {
        SAMLObject object = samlSystemService.build(AuthnRequest.DEFAULT_ELEMENT_NAME);

        samlSystemService.getResponseAndValidateSchema(object);
    }

    @Test(expectedExceptions = SAMLException.class, expectedExceptionsMessageRegExp = SamlExceptionText.INVALID_SCHEMA_RESPONSE)
    public void shouldThrowExceptionInvalidSchema() throws SAMLException {
        SAMLObject object = samlSystemService.build(Response.DEFAULT_ELEMENT_NAME);

        samlSystemService.getResponseAndValidateSchema(object);
    }

    public void shouldGetResultNotNull() throws SAMLException {
        Response parameter = samlSystemService.build(Response.DEFAULT_ELEMENT_NAME);
        Status status = samlSystemService.build(Status.DEFAULT_ELEMENT_NAME);
        parameter.setStatus(status);
        parameter.setID("test_id");
        parameter.setVersion(SAMLVersion.VERSION_20);
        parameter.setIssueInstant(ISSUE_INSTANT);

        Response result = samlSystemService.getResponseAndValidateSchema(parameter);

        Assert.assertNotNull(result);
    }

    @Test(expectedExceptions = SAMLException.class, expectedExceptionsMessageRegExp = SamlExceptionText.STATUSCODE_WAS_NOT_SUCCESS)
    public void shouldThrowExceptionStatusCode() throws SAMLException {
        Response response = mock(Response.class, RETURNS_DEEP_STUBS);
        when(response.getStatus().getStatusCode().getValue()).thenReturn(StatusCode.AUTHN_FAILED_URI);

        samlSystemService.checkStatusCode(response);
    }

    public void shouldNotThrowExceptionStatusCode() throws SAMLException {
        Response response = mock(Response.class, RETURNS_DEEP_STUBS);
        when(response.getStatus().getStatusCode().getValue()).thenReturn(StatusCode.SUCCESS_URI);

        samlSystemService.checkStatusCode(response);
    }

    @Test(expectedExceptions = SAMLException.class, expectedExceptionsMessageRegExp = SamlExceptionText.NO_ASSERTIONS_FOUND)
    public void shouldThrowExceptionNoAssertionsFound() throws SAMLException {
        Response response = mock(Response.class, RETURNS_DEEP_STUBS);
        when(response.getAssertions()).thenReturn(Collections.emptyList());

        samlSystemService.getCheckedAssertion(response);
    }

    @Test(expectedExceptions = SAMLException.class, expectedExceptionsMessageRegExp = SamlExceptionText.MORE_THAN_ONE_ASSERTION_WAS_FOUND)
    public void shouldThrowExceptionMoreThanOneAssertion() throws SAMLException {
        Response response = mock(Response.class, RETURNS_DEEP_STUBS);
        when(response.getAssertions().size()).thenReturn(2);

        samlSystemService.getCheckedAssertion(response);
    }

    public void shouldGetAssertion() throws SAMLException {
        Response response = mock(Response.class, RETURNS_DEEP_STUBS);
        Assertion assertion = mock(Assertion.class);
        when(response.getAssertions().get(0)).thenReturn(assertion);

        Assertion assertionResult = samlSystemService.getCheckedAssertion(response);

        Assert.assertEquals(assertion, assertionResult);
    }

    @Test(expectedExceptions = SAMLException.class, expectedExceptionsMessageRegExp = SamlExceptionText.CONDITIONS_ARE_NOT_YET_ACTIVE)
    public void shouldThrowExceptionNotYetActive() throws SAMLException {
        Assertion assertion = mock(Assertion.class, RETURNS_DEEP_STUBS);
        when(assertion.getConditions().getNotBefore()).thenReturn(ISSUE_INSTANT.plusHours(1));
        when(assertion.getConditions().getNotOnOrAfter()).thenReturn(ISSUE_INSTANT.plusHours(1));

        samlSystemService.checkConditions(assertion);
    }

    @Test(expectedExceptions = SAMLException.class, expectedExceptionsMessageRegExp = SamlExceptionText.CONDITIONS_HAVE_EXPIRED)
    public void shouldThrowExceptionHaveExpired() throws SAMLException {
        Assertion assertion = mock(Assertion.class, RETURNS_DEEP_STUBS);
        when(assertion.getConditions().getNotBefore()).thenReturn(ISSUE_INSTANT.minusHours(1));
        when(assertion.getConditions().getNotOnOrAfter()).thenReturn(ISSUE_INSTANT.minusHours(1));

        samlSystemService.checkConditions(assertion);
    }

    public void shouldNotThrowExceptionConditions() throws SAMLException {
        Assertion assertion = mock(Assertion.class, RETURNS_DEEP_STUBS);
        when(assertion.getConditions().getNotBefore()).thenReturn(ISSUE_INSTANT.minusHours(1));
        when(assertion.getConditions().getNotOnOrAfter()).thenReturn(ISSUE_INSTANT.plusHours(1));

        samlSystemService.checkConditions(assertion);
    }

    public void shouldReturnSomeValue() {
        Assertion assertion = mock(Assertion.class, RETURNS_DEEP_STUBS);
        String subjectNameID = "test@test.ru";
        when(assertion.getSubject().getNameID().getValue()).thenReturn(subjectNameID);

        String result = samlSystemService.getSubjectNameId(assertion);

        Assert.assertEquals(subjectNameID, result);
    }

    public void shouldGetValidator() throws IOException, URISyntaxException, SAMLException {
        String certificate = getResourceFileAsString("certs/correct.key.pem");

        Validator<Signature> validator = samlSystemService.getValidator(certificate);

        Assert.assertNotNull(validator);
    }

    @Test(expectedExceptions = SAMLException.class, expectedExceptionsMessageRegExp = SamlExceptionText.STRING_CERTIFICATE_IS_INCORRECT)
    public void shouldThrowExceptionCertificateIsIncorrect() throws IOException, URISyntaxException, SAMLException {
        String certificate = getResourceFileAsString("certs/bad.key.pem");

        samlSystemService.getValidator(certificate);
    }

    public void shouldGetXmlObject() throws SAMLException, IOException, URISyntaxException {
        String xml = getResourceFileAsString("xml/correct.response.xml");

        XMLObject xmlObject = samlSystemService.convertStringToXmlObject(xml);

        Assert.assertNotNull(xmlObject);
    }

    @Test(expectedExceptions = SAMLException.class, expectedExceptionsMessageRegExp = SamlExceptionText.PROBLEM_PARSING_XML_OF_THE_RESPONSE)
    public void shouldThrowExceptionParsingXml() throws SAMLException, IOException, URISyntaxException {
        String xml = getResourceFileAsString("xml/bad.response.xml");

        samlSystemService.convertStringToXmlObject(xml);
    }

    private String getResourceFileAsString(String path) throws IOException {
        try (InputStream input = getClass().getClassLoader().getResourceAsStream(path)) {
            return IOUtils.toString(input);
        }
    }

    public void shouldGetStringFromXmlObject() throws SAMLException, IOException, URISyntaxException {
        XMLObject xmlObject = samlSystemService.build(AuthnContext.DEFAULT_ELEMENT_NAME);

        String xml = samlSystemService.convertXmlObjectToString(xmlObject);

        Assert.assertNotNull(xml);
        Assert.assertTrue(xml.contains(xmlObject.getElementQName().getNamespaceURI()));
    }

    @Test(expectedExceptions = SAMLException.class, expectedExceptionsMessageRegExp = SamlExceptionText.PROBLEM_CONVERT_MASK_TO_STRING_FOR_TEST)
    public void shouldThrow() throws SAMLException, IOException, URISyntaxException {
        XMLObject xmlObject = mock(XMLObject.class);

        samlSystemService.convertXmlObjectToString(xmlObject);
    }

    @SuppressWarnings("unchecked")
    @Test(expectedExceptions = SAMLException.class, expectedExceptionsMessageRegExp = SamlExceptionText.MASK_DOES_NOT_HAVE_SIGNATURE_FOR_TEST)
    public void shouldThrowExceptionDoesNotHaveSignature() throws SAMLException {
        SignableXMLObject signableXMLObject = mock(SignableXMLObject.class);
        doReturn(false).when(signableXMLObject).isSigned();
        Validator<Signature> validator = mock(Validator.class);

        samlSystemService.validateMandatorySignature(validator, signableXMLObject);
    }

    @SuppressWarnings("unchecked")
    @Test(expectedExceptions = SAMLException.class, expectedExceptionsMessageRegExp = SamlExceptionText.MASK_HAS_INVALID_SIGNATURE_FOR_TEST)
    public void shouldThrowExceptionInvalidSignature() throws SAMLException, ValidationException {
        SignableXMLObject signableXMLObject = mock(SignableXMLObject.class);
        doReturn(true).when(signableXMLObject).isSigned();
        doReturn(mock(Signature.class)).when(signableXMLObject).getSignature();
        Validator<Signature> validator = mock(Validator.class);
        doThrow(new ValidationException("Test")).when(validator).validate(any());

        samlSystemService.validateMandatorySignature(validator, signableXMLObject);
    }

    @SuppressWarnings("unchecked")
    public void shouldNotThrowExceptionInvalidSignature() throws ValidationException, SAMLException {
        SignableXMLObject signableXMLObject = mock(SignableXMLObject.class);
        doReturn(true).when(signableXMLObject).isSigned();
        doReturn(mock(Signature.class)).when(signableXMLObject).getSignature();
        Validator<Signature> validator = mock(Validator.class);
        doNothing().when(validator).validate(any());

        samlSystemService.validateMandatorySignature(validator, signableXMLObject);
    }

    @SuppressWarnings("unchecked")
    public void shouldNotThrowExceptionNotHaveSignature() throws SAMLException {
        SignableXMLObject signableXMLObject = mock(SignableXMLObject.class);
        doReturn(false).when(signableXMLObject).isSigned();
        Validator<Signature> validator = mock(Validator.class);

        samlSystemService.validateOptionalSignature(validator, signableXMLObject);
    }

    public void shouldGetAttributeValues() throws SAMLException {
        XMLObject xmlObject = mock(XMLObject.class, RETURNS_DEEP_STUBS);
        when(xmlObject.getDOM().getTextContent()).thenReturn("testValue");

        Attribute attribute = mock(Attribute.class);
        doReturn(Collections.singletonList(xmlObject)).when(attribute).getAttributeValues();
        doReturn("testAttr").when(attribute).getName();

        AttributeStatement attributeStatement = mock(AttributeStatement.class);
        doReturn(Collections.singletonList(attribute)).when(attributeStatement).getAttributes();

        Assertion assertion = mock(Assertion.class);
        doReturn(Collections.singletonList(attributeStatement)).when(assertion).getAttributeStatements();
        Map result = Collections.singletonMap("testAttr", Collections.singletonList("testValue"));

        Map values = samlSystemService.getAttributeValues(assertion);

        Assert.assertEquals(result, values);
    }

    public void shouldGetCertificate() throws CertificateException, IOException, URISyntaxException {
        String certificate = getResourceFileAsString("certs/correct.key.without.headers.pem");

        samlSystemService.getCertificate(certificate);
    }
}