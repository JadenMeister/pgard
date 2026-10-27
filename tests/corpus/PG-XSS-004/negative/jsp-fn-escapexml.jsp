<!-- corpus: expect=none -->
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<p>You searched for ${fn:escapeXml(param.q)}</p>
