<?php // corpus: expect=PG-SQL-007
function sorted($conn) {
    $column = $_GET['sort'];
    if (!in_array($column, ['name', 'email'], true)) {
        error_log('bad sort');
    }
    return mysqli_query($conn, "SELECT * FROM users ORDER BY $column");
}
