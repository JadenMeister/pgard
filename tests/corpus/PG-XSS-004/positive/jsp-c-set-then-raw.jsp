<!-- corpus: expect=PG-XSS-004 -->
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<c:set var="q" value="${param.q}"/>
<p>${q}</p>
