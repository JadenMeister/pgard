<?php // corpus: expect=PG-SQL-007
function totals(Request $request) {
    return Order::selectRaw("sum({$request->input('col')}) as total")->groupBy('user_id')->havingRaw('total > ' . $request->input('min'))->get();
}
