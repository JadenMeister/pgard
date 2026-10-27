<?php // corpus: expect=PG-SQL-006
function sorted($conn) {
    $column = $_GET['sort'];
    if (!preg_match('/[a-z_]+/', $column)) {
        return;
    }
    return mysqli_query($conn, "SELECT * FROM users ORDER BY $column");
}
