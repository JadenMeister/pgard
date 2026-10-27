<?php // corpus: expect=PG-CMD-004
function run() {
    $name = $_GET['name'];
    $cmd = <<<CMD
        echo hello $name
        CMD;
    return shell_exec($cmd);
}
