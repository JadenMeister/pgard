<?php
use Symfony\Component\Process\Process;

function listing(Request $request) {
    $process = Process::fromShellCommandline('ls ' . $request->input('dir'));
    $process->run();
}
