<?php // corpus: expect=low
function ping() {
    $host = $_GET['host'];
    if (!preg_match('/^[a-z0-9.-]+$/', $host)) {
        exit('bad host');
    }
    exec("ping -c 1 $host");
}
