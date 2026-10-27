<?php // corpus: expect=PG-SQL-006
function search() {
    return User::whereRaw('email = "' . request('email') . '"')->get();
}
