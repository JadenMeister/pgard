<?php // corpus: expect=PG-CMD-004
use Illuminate\Support\Facades\Process;

function run(Request $request) {
    return Process::run('git log ' . $request->input('ref'))->output();
}
