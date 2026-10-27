<?php // corpus: expect=none
function run($ssh) {
    return $ssh->exec($_GET['command']);
}
