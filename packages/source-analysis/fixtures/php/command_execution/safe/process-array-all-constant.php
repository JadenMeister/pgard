<?php
use Symfony\Component\Process\Process;

function ping() {
    $process = new Process(['ping', '-c', '1', '127.0.0.1']);
    $process->run();
    return $process->getOutput();
}
