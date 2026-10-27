<?php // corpus: expect=none
use Symfony\Component\Process\Process;

function run() {
    $process = new Process(['sh', '-c', 'ls -la | wc -l']);
    $process->run();
}
