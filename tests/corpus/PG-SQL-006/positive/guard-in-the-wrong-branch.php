<?php // corpus: expect=PG-SQL-006
function sorted($conn) {
    $column = $_GET['sort'];
    if (in_array($column, ['name', 'email'], true)) {
        $ok = true;
    } else {
        return mysqli_query($conn, "SELECT * FROM users ORDER BY $column");
    }
}
