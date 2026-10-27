<?php // corpus: expect=none
function ping() {
    $host = $_GET['host'];
    error_log("pinging $host");
    exec('ping -c 1 127.0.0.1');
}
