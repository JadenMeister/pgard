<?php // corpus: expect=PG-CMD-005
function archive() {
    $args = ['tar', '-czf', 'out.tgz'];
    $args[] = $_POST['path'];
    $process = new \Symfony\Component\Process\Process($args);
    $process->run();
}
