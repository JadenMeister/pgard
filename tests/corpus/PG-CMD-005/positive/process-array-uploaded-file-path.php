<?php // corpus: expect=PG-CMD-005
use Symfony\Component\Process\Process;

function thumbnail(Request $request) {
    $process = new Process(['convert', $request->files->get('img')->getPathname(), 'out.png']);
    $process->run();
}
