<?php // corpus: expect=PG-CMD-005
function tail() {
    $handle = popen('tail -n 20 ' . $_GET['log'], 'r');
    return fread($handle, 4096);
}
