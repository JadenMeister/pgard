<!-- corpus: expect=PG-XSS-004 -->
<html><body>
<p>Hello <%= request.getParameter("name") %></p>
</body></html>
