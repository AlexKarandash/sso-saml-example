package com.subbotin.saml.utils;

import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

public final class SamlSystemUtils {
    public static final String ISSUER_NAME = "https://realtimeboard.com";
    public static final int BACKLASH_FOR_MESSAGE_IN_SECONDS = 300;
    public static String SESSION_USER = "SESSION_USER";

    public static Logger logger = LoggerFactory.getLogger(SamlSystemUtils.class);

    public static void init() {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            logger.error("Problem while bootstrapping openSAML library", e);
        }
    }

    public static String generateId() {
        return "_" + UUID.randomUUID();
    }
}
