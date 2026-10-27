<!-- corpus: expect=PG-XSS-004 -->
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<c:out value="${param.q}" escapeXml="false"/>
