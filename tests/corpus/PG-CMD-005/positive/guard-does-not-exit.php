<?php // corpus: expect=PG-CMD-005
function ping() {
    $host = $_GET['host'];
    if (!preg_match('/^[a-z0-9.-]+$/', $host)) {
        error_log('suspicious host');
    }
    exec("ping -c 1 $host");
}
