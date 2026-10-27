<?php // corpus: expect=PG-SQL-006
use Illuminate\Support\Facades\DB;

function find(Request $request) {
    return DB::select("SELECT * FROM users WHERE name = '" . $request->input('name') . "' AND active = ?", [1]);
}
