<?php // corpus: expect=PG-CMD-004
use Symfony\Component\Process\Process;

function run(Request $request) {
    $process = Process::fromShellCommandline('ls ' . $request->input('dir'));
    $process->run();
    return $process->getOutput();
}
