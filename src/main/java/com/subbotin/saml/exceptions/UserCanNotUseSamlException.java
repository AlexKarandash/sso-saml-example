package com.subbotin.saml.exceptions;

public class UserCanNotUseSamlException extends RuntimeException {
    public UserCanNotUseSamlException(String email) {
        super(String.format("User %s can not use SAML", email));
    }
}
