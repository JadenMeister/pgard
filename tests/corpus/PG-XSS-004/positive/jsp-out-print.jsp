<!-- corpus: expect=PG-XSS-004 -->
<html><body>
<% out.println("<p>" + request.getParameter("q") + "</p>"); %>
</body></html>
