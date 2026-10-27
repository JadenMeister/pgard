<?php // corpus: expect=PG-CMD-004
function lookup() {
    $host = $_GET['host'];
    return shell_exec("nslookup $host");
}
