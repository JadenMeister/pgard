<?php // corpus: expect=PG-SQL-006
function find($conn) {
    return mysqli_query($conn, "SELECT * FROM users WHERE id = {$_POST['id']}");
}
