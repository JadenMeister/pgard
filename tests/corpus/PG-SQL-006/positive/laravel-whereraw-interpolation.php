<?php // corpus: expect=PG-SQL-006
function search(Request $request) {
    return User::whereRaw("name = '{$request->input('name')}'")->get();
}
