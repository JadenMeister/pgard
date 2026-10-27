<!-- corpus: expect=PG-XSS-004 -->
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<html><body>
<p>You searched for ${param.q}</p>
</body></html>
