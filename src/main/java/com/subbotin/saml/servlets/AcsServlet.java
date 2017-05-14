package com.subbotin.saml.servlets;

import com.subbotin.saml.common.User;
import com.subbotin.saml.common.Users;
import com.subbotin.saml.exceptions.UserCanNotUseSamlException;
import com.subbotin.saml.saml.SamlResponse;
import com.subbotin.saml.saml.SamlSettings;
import com.subbotin.saml.services.SamlService;
import com.subbotin.saml.services.SamlServiceImpl;
import com.subbotin.saml.utils.SamlSystemUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AcsServlet extends HttpServlet {
    private SamlService samlService = new SamlServiceImpl();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        SamlResponse samlResponse = samlService.createSamlResponse(request.getParameter("SAMLResponse"));
        String email = samlResponse.getSubjectNameId();
        SamlSettings samlSettings = samlService.getSamlSettings(email);
        if (samlSettings == null) {
            throw new UserCanNotUseSamlException(email);
        }

        samlService.checkSignature(samlResponse, samlSettings.getX509Certificate());

        String userName = samlService.getUserName(samlResponse);
        User user = Users.getUser(email);
        if (user == null) {
            user = new User(email, userName);
            Users.addUser(user);
        } else {
            user.setName(userName);
        }

        request.getSession().setAttribute(SamlSystemUtils.SESSION_USER, user);
        response.sendRedirect("index.jsp");
    }
}