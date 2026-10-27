<?php
use Symfony\Component\Process\Process;

function ping() {
    $process = new Process(['ping', '-c', '1', $_GET['host']]);
    $process->run();
    return $process->getOutput();
}
