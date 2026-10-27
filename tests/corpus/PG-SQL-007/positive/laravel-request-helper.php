<?php // corpus: expect=PG-SQL-007
function search() {
    return User::whereRaw('email = "' . request('email') . '"')->get();
}
