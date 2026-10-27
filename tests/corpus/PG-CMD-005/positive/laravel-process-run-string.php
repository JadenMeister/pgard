<?php // corpus: expect=PG-CMD-005
use Illuminate\Support\Facades\Process;

function run(Request $request) {
    return Process::run('git log ' . $request->input('ref'))->output();
}
