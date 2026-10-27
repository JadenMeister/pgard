<?php // corpus: expect=none
use Symfony\Component\Process\Process;

function history() {
    $process = new Process(['git', 'log', '--oneline', '-n', '5']);
    $process->run();
    return $process->getOutput();
}
