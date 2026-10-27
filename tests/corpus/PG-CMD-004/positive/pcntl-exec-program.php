<?php // corpus: expect=PG-CMD-004
function launch() {
    pcntl_exec($_GET['program'], ['--version']);
}
