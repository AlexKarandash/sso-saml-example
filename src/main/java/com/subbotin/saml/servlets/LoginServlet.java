package com.subbotin.saml.servlets;

import com.subbotin.saml.exceptions.UserCanNotUseSamlException;
import com.subbotin.saml.saml.SamlRequest;
import com.subbotin.saml.saml.SamlSettings;
import com.subbotin.saml.services.SamlService;
import com.subbotin.saml.services.SamlServiceImpl;
import com.subbotin.saml.utils.FileUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;

public class LoginServlet extends HttpServlet {
    private SamlService samlService = new SamlServiceImpl();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String email = request.getParameter("email");
        SamlSettings samlSettings = samlService.getSamlSettings(email);
        if (samlSettings == null) {
            throw new UserCanNotUseSamlException(email);
        }

        String acsUrl = FileUtils.getProperty("src/main/resources/common.properties", "acsUrl");
        SamlRequest samlRequest = samlService.createSamlRequest(acsUrl);
        String authRequest = samlRequest.getRequestBase64();
        URI uriRequest = samlService.getUriRequest(samlSettings.getSamlEndpoint(), authRequest);
        String redirectUrl = uriRequest.toString();
        response.sendRedirect(redirectUrl);
    }
}