<?php // corpus: expect=PG-SQL-006
use Illuminate\Support\Facades\DB;

function run(Request $request) {
    DB::unprepared('UPDATE users SET role = ' . $request->role);
}
