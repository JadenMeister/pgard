<?php // corpus: expect=PG-SQL-006
function find($conn) {
    $result = mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $_GET['name'] . "'");
    return mysqli_fetch_all($result);
}
