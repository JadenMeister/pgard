<?php // corpus: expect=PG-SQL-007
function find($conn) {
    $query = fn($table) => "SELECT * FROM " . $table;
    return mysqli_query($conn, $query($_GET['table']));
}
