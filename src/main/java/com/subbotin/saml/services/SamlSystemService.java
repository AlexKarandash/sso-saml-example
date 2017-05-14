package com.subbotin.saml.services;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.validation.Validator;

import javax.xml.namespace.QName;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;

public interface SamlSystemService {
    AuthnRequest createAuthnRequest(String assertionConsumerServiceUrl, String requestId, DateTime issueInstant, String issuerName);

    @SuppressWarnings("unchecked")
    <T extends SAMLObject> T build(QName qName);

    Response getResponseAndValidateSchema(XMLObject response) throws SAMLException;

    @SuppressWarnings("TypeMayBeWeakened")
    void checkStatusCode(Response response) throws SAMLException;

    Assertion getCheckedAssertion(Response response) throws SAMLException;

    void checkConditions(Assertion assertion) throws SAMLException;

    String getSubjectNameId(Assertion assertion);

    Validator<Signature> getValidator(String certificate) throws SAMLException;

    Certificate getCertificate(String certificate) throws CertificateException;

    void validateMandatorySignature(Validator<Signature> signatureValidator, SignableXMLObject signableXMLObject) throws SAMLException;

    void validateOptionalSignature(Validator<Signature> signatureValidator, SignableXMLObject signableXMLObject) throws SAMLException;

    Map<String, List<String>> getAttributeValues(Assertion assertion);

    XMLObject convertStringToXmlObject(String xmlObject) throws SAMLException;

    String convertXmlObjectToString(XMLObject xmlObject) throws SAMLException;
}

