<!-- corpus: expect=PG-XSS-004 -->
<html><body>
<input type="text" name="q" value="${param.q}">
</body></html>
