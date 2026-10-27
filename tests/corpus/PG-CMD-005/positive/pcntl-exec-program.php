<?php // corpus: expect=PG-CMD-005
function launch() {
    pcntl_exec($_GET['program'], ['--version']);
}
