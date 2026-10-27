<?php // corpus: expect=PG-CMD-004
use Symfony\Component\Process\Process;

function run() {
    $process = new Process('ls ' . $_GET['dir']);
    $process->run();
}
