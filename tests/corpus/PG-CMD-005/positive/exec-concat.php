<?php // corpus: expect=PG-CMD-005
function ping() {
    exec('ping -c 1 ' . $_GET['host'], $output);
    return $output;
}
