package com.subbotin.saml.servlets;

import com.subbotin.saml.utils.SamlSystemUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class LogoutServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        request.getSession().removeAttribute(SamlSystemUtils.SESSION_USER);
        response.sendRedirect("index.jsp");
    }
}