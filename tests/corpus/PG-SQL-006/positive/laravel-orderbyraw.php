<?php // corpus: expect=PG-SQL-006
function listing(Request $request) {
    return Post::query()->orderByRaw($request->input('sort') . ' desc')->get();
}
