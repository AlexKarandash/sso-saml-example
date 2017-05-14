package com.subbotin.saml.utils;

public final class SamlExceptionText {
    public static final String XMLOBJECT_NOT_CAST_TO_RESPONSE = "XMLObject does not cast to Response";
    public static final String INVALID_SCHEMA_RESPONSE = "Invalid schema response";
    public static final String STATUSCODE_WAS_NOT_SUCCESS = "StatusCode was not a success";
    public static final String NO_ASSERTIONS_FOUND = "No assertions found";
    public static final String MORE_THAN_ONE_ASSERTION_WAS_FOUND = "More than one assertion was found";
    public static final String CONDITIONS_ARE_NOT_YET_ACTIVE = "Conditions are not yet active";
    public static final String CONDITIONS_HAVE_EXPIRED = "Conditions have expired";
    public static final String STRING_CERTIFICATE_IS_INCORRECT = "String certificate is incorrect";
    public static final String PROBLEM_PARSING_XML_OF_THE_RESPONSE = "Problem parsing XML of the response";
    public static final String PROBLEM_CONVERT_MASK_TO_STRING = "Problem convert %s to string";
    public static final String PROBLEM_CONVERT_MASK_TO_STRING_FOR_TEST = "Problem convert .* to string";
    public static final String MASK_DOES_NOT_HAVE_SIGNATURE = "%s does not have signature";
    public static final String MASK_DOES_NOT_HAVE_SIGNATURE_FOR_TEST = ".* does not have signature";
    public static final String MASK_HAS_INVALID_SIGNATURE = "%s has invalid signature";
    public static final String MASK_HAS_INVALID_SIGNATURE_FOR_TEST = ".* has invalid signature";
    public static final String PROBLEM_DECODE_RESPONSE_FROM_BASE64 = "Problem decode response from Base64";
    public static final String PROBLEM_DEFLATE_AND_ENCODE_REQUEST_TO_BASE64 = "Problem deflate AuthnRequest and encode to Base64";

    private SamlExceptionText() {}
}
