<%@ page import="com.subbotin.saml.common.User" %>
<%@ page import="com.subbotin.saml.utils.SamlSystemUtils" %>
<%@ page import="com.subbotin.saml.common.Users" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <meta charset="UTF-8">
    <title>Тег META, атрибут charset</title>
</head>
<body>
<%
    SamlSystemUtils.init();
    User user = (User) request.getSession().getAttribute(SamlSystemUtils.SESSION_USER);
    if (user != null) {
%>
<h2>Добрый день, <%=user.getName()%> (<%=user.getEmail()%>). Вам доступен этот ресурс</h2>
<br>
<a href="logout">Logout</a>
<% } else { %>
<h2>Для доступа к ресурсу Вам необходимо залогиниться, всего юзеров <%=Users.getSize()%></h2>
<form action="login" method="post">
    <p><b>Укажите Ваш Email</b></p>
    <p><input type="email" name="email"></p>
    <p><input type="submit"></p>
</form>
<% } %>
</body>
</html>
