<?php // corpus: expect=PG-SQL-006
function totals(Request $request) {
    return Order::selectRaw("sum({$request->input('col')}) as total")->groupBy('user_id')->havingRaw('total > ' . $request->input('min'))->get();
}
