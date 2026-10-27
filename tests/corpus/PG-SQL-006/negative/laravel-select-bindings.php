<?php // corpus: expect=none
use Illuminate\Support\Facades\DB;

function find(Request $request) {
    return DB::select('SELECT * FROM users WHERE id = ? AND active = ?', [$request->input('id'), 1]);
}
