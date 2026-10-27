<?php // corpus: expect=PG-CMD-005
function run() {
    return call_user_func('system', 'ping -c 1 ' . $_GET['host']);
}
