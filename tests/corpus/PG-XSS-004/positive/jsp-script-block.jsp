<!-- corpus: expect=PG-XSS-004 -->
<html><body>
<script>
var q = "${param.q}";
</script>
</body></html>
