<?php // corpus: expect=PG-CMD-005
function history() {
    $process = proc_open('git log ' . $_GET['ref'], [1 => ['pipe', 'w']], $pipes);
    return stream_get_contents($pipes[1]);
}
