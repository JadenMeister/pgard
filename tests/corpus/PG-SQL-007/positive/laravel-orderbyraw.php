<?php // corpus: expect=PG-SQL-007
function listing(Request $request) {
    return Post::query()->orderByRaw($request->input('sort') . ' desc')->get();
}
