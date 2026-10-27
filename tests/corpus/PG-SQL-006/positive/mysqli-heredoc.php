<?php // corpus: expect=PG-SQL-006
function find($conn) {
    $name = $_GET['name'];
    $sql = <<<SQL
        SELECT * FROM users WHERE name = '$name'
        SQL;
    return mysqli_query($conn, $sql);
}
