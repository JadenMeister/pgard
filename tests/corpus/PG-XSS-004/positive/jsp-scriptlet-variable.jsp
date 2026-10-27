<!-- corpus: expect=PG-XSS-004 -->
<% String name = request.getParameter("name"); %>
<html><body>
<h1><%= name %></h1>
</body></html>
