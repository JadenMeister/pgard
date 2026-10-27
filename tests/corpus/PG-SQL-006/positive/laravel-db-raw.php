<?php // corpus: expect=PG-SQL-006
use Illuminate\Support\Facades\DB;

function report(Request $request) {
    return DB::table('orders')->select(DB::raw("count(*) as {$request->input('alias')}"))->get();
}
