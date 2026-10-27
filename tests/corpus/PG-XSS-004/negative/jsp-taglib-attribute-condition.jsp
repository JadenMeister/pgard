<!-- corpus: expect=none -->
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<c:if test="${param.admin == '1'}"><p>admin view</p></c:if>
