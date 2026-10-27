<?php // corpus: expect=PG-CMD-004
function tail() {
    $handle = popen('tail -n 20 ' . $_GET['log'], 'r');
    return fread($handle, 4096);
}
