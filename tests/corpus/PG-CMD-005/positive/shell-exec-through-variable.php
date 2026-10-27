<?php // corpus: expect=PG-CMD-005
function lookup() {
    $host = $_GET['host'];
    return shell_exec("nslookup $host");
}
