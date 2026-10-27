<?php // corpus: expect=PG-CMD-005
function run() {
    $name = $_GET['name'];
    $cmd = <<<CMD
        echo hello $name
        CMD;
    return shell_exec($cmd);
}
