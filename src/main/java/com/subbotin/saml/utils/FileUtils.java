package com.subbotin.saml.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public final class FileUtils {
    public static String getProperty(String propertiesFileName, String property) throws IOException {
        Properties properties = new Properties();
        properties.load(new FileInputStream(propertiesFileName));
        return properties.getProperty(property);
    }
}
