<?php // corpus: expect=PG-SQL-007
function find($conn) {
    return mysqli_query($conn, sprintf("SELECT * FROM users WHERE name = '%s'", $_GET['name']));
}
