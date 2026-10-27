<?php // corpus: expect=PG-SQL-007
function search(Request $request) {
    return User::whereRaw("name = '{$request->input('name')}'")->get();
}
