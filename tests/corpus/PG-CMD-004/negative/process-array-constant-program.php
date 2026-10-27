<?php // corpus: expect=none
use Symfony\Component\Process\Process;

function history() {
    $process = new Process(['git', 'log', '--end-of-options', $_GET['ref'], '--']);
    $process->run();
    return $process->getOutput();
}
