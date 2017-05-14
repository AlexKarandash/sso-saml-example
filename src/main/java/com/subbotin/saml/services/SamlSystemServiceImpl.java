package com.subbotin.saml.services;

import com.subbotin.saml.utils.SamlExceptionText;
import com.subbotin.saml.utils.SamlSystemUtils;
import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.validator.ResponseSchemaValidator;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.Validator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class SamlSystemServiceImpl implements SamlSystemService {
    public static Logger logger = LoggerFactory.getLogger(SamlSystemServiceImpl.class);

    @Override
    public AuthnRequest createAuthnRequest(String assertionConsumerServiceUrl, String requestId, DateTime issueInstant, String issuerName) {
        AuthnRequest request = build(AuthnRequest.DEFAULT_ELEMENT_NAME);
        request.setID(requestId);
        request.setVersion(SAMLVersion.VERSION_20);
        request.setIssueInstant(issueInstant);
        request.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        request.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);

        Issuer issuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(issuerName);
        request.setIssuer(issuer);

        NameIDPolicy nameIDPolicy = build(NameIDPolicy.DEFAULT_ELEMENT_NAME);
        nameIDPolicy.setFormat(NameIDType.EMAIL);
        request.setNameIDPolicy(nameIDPolicy);

        RequestedAuthnContext requestedAuthnContext = build(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
        request.setRequestedAuthnContext(requestedAuthnContext);

        AuthnContextClassRef authnContextClassRef = build(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.PPT_AUTHN_CTX);
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

        return request;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T extends SAMLObject> T build(QName qName) {
        return (T) Configuration.getBuilderFactory().getBuilder(qName).buildObject(qName);
    }

    @Override
    public Response getResponseAndValidateSchema(XMLObject response) throws SAMLException {
        try {
            if (!Response.class.isInstance(response)) {
                throw new SAMLException(SamlExceptionText.XMLOBJECT_NOT_CAST_TO_RESPONSE);
            }
            Response resultResponse = (Response) response;
            new ResponseSchemaValidator().validate(resultResponse);
            return resultResponse;
        } catch (ValidationException e) {
            logger.error(e.getMessage(), e);
            throw new SAMLException(SamlExceptionText.INVALID_SCHEMA_RESPONSE, e);
        }
    }

    @Override
    @SuppressWarnings("TypeMayBeWeakened")
    public void checkStatusCode(Response response) throws SAMLException {
        String statusCode = response.getStatus().getStatusCode().getValue();
        if (!StringUtils.equals(statusCode, StatusCode.SUCCESS_URI)) {
            throw new SAMLException(SamlExceptionText.STATUSCODE_WAS_NOT_SUCCESS);
        }
    }

    @Override
    public Assertion getCheckedAssertion(Response response) throws SAMLException {
        List<Assertion> assertionList = response.getAssertions();
        if (assertionList.isEmpty()) {
            throw new SAMLException(SamlExceptionText.NO_ASSERTIONS_FOUND);
        } else if (assertionList.size() > 1) {
            throw new SAMLException(SamlExceptionText.MORE_THAN_ONE_ASSERTION_WAS_FOUND);
        }
        return assertionList.get(0);
    }

    @Override
    public void checkConditions(Assertion assertion) throws SAMLException {
        Conditions conditions = assertion.getConditions();
        Date now = DateTime.now().toDate();
        Date conditionNotBefore = conditions.getNotBefore().minusSeconds(SamlSystemUtils.BACKLASH_FOR_MESSAGE_IN_SECONDS).toDate();
        Date conditionNotOnOrAfter = conditions.getNotOnOrAfter().plusSeconds(SamlSystemUtils.BACKLASH_FOR_MESSAGE_IN_SECONDS).toDate();
        if (now.before(conditionNotBefore)) {
            throw new SAMLException(SamlExceptionText.CONDITIONS_ARE_NOT_YET_ACTIVE);
        } else if (now.after(conditionNotOnOrAfter) || now.equals(conditionNotOnOrAfter)) {
            throw new SAMLException(SamlExceptionText.CONDITIONS_HAVE_EXPIRED);
        }
    }

    @Override
    public String getSubjectNameId(Assertion assertion) {
        return assertion.getSubject().getNameID().getValue();
    }

    @Override
    public Validator<Signature> getValidator(String certificate) throws SAMLException {
        try {
            Certificate cert = getCertificate(certificate);
            BasicCredential credential = new BasicCredential();
            credential.setPublicKey(cert.getPublicKey());
            return new SignatureValidator(credential);
        } catch (CertificateException e) {
            logger.error(e.getMessage(), e);
            throw new SAMLException(SamlExceptionText.STRING_CERTIFICATE_IS_INCORRECT, e);
        }
    }

    @Override
    public Certificate getCertificate(String certificate) throws CertificateException {
        String beginHeader = "-----BEGIN CERTIFICATE-----";
        String endHeader = "-----END CERTIFICATE-----";
        StringBuilder stringBuilder = new StringBuilder();
        if (!certificate.startsWith(beginHeader)) {
            stringBuilder.append(beginHeader);
            stringBuilder.append("\n");
        }
        stringBuilder.append(certificate);
        if (!certificate.endsWith(endHeader)) {
            stringBuilder.append("\n");
            stringBuilder.append(endHeader);
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return cf.generateCertificate(new ByteArrayInputStream(stringBuilder.toString().getBytes()));
    }

    @Override
    public void validateMandatorySignature(Validator<Signature> signatureValidator, SignableXMLObject signableXMLObject) throws SAMLException {
        if (!signableXMLObject.isSigned()) {
            throw new SAMLException(String.format(SamlExceptionText.MASK_DOES_NOT_HAVE_SIGNATURE, signableXMLObject.getElementQName()));
        }

        validateSignature(signatureValidator, signableXMLObject.getSignature(), getErrorTextForValidateSignature(signableXMLObject));
    }

    @Override
    public void validateOptionalSignature(Validator<Signature> signatureValidator, SignableXMLObject signableXMLObject) throws SAMLException {
        if (signableXMLObject.isSigned()) {
            validateSignature(signatureValidator, signableXMLObject.getSignature(), getErrorTextForValidateSignature(signableXMLObject));
        }
    }

    private String getErrorTextForValidateSignature(XMLObject signableXMLObject) {
        return String.format(SamlExceptionText.MASK_HAS_INVALID_SIGNATURE, signableXMLObject.getElementQName());
    }

    private void validateSignature(Validator<Signature> signatureValidator, Signature signature, String textError) throws SAMLException {
        try {
            signatureValidator.validate(signature);
        } catch (ValidationException | RuntimeException e) {
            logger.error(e.getMessage(), e);
            throw new SAMLException(textError, e);
        }
    }

    @Override
    public Map<String, List<String>> getAttributeValues(Assertion assertion) {
        Map<String, List<String>> attributes = new HashMap<>();
        for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
            for (Attribute attr : attributeStatement.getAttributes()) {
                List<String> values = attr.getAttributeValues().stream().map(value -> value.getDOM().getTextContent()).collect(Collectors.toList());
                attributes.put(attr.getName(), values);
            }
        }
        return attributes;
    }

    @Override
    public XMLObject convertStringToXmlObject(String xmlObject) throws SAMLException {
        try {
            Element root = new BasicParserPool().parse(new ByteArrayInputStream(xmlObject.getBytes())).getDocumentElement();
            return Configuration.getUnmarshallerFactory().getUnmarshaller(root).unmarshall(root);
        } catch (XMLParserException | UnmarshallingException e) {
            logger.error(e.getMessage(), e);
            throw new SAMLException(SamlExceptionText.PROBLEM_PARSING_XML_OF_THE_RESPONSE, e);
        }
    }

    @Override
    public String convertXmlObjectToString(XMLObject xmlObject) throws SAMLException {
        try {
            Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(xmlObject);
            Element dom = marshaller.marshall(xmlObject);
            StringWriter stringWriter = new StringWriter();
            XMLHelper.writeNode(dom, stringWriter);
            return stringWriter.toString();
        } catch (RuntimeException | MarshallingException e) {
            logger.error(e.getMessage(), e);
            throw new SAMLException(String.format(SamlExceptionText.PROBLEM_CONVERT_MASK_TO_STRING, xmlObject.getElementQName()), e);
        }
    }
}

