<?php // corpus: expect=PG-CMD-005
function run() {
    $runner = 'shell_exec';
    return $runner('nslookup ' . $_GET['host']);
}
