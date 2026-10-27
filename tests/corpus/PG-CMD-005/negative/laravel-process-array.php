<?php // corpus: expect=none
use Illuminate\Support\Facades\Process;

function history(Request $request) {
    return Process::run(['git', 'log', $request->input('ref')])->output();
}
