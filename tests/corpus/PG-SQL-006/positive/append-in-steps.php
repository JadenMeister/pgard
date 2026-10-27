<?php // corpus: expect=PG-SQL-006
function search($conn) {
    $sql = "SELECT * FROM users WHERE 1 = 1";
    if (!empty($_GET['name'])) {
        $sql .= " AND name = '" . $_GET['name'] . "'";
    }
    return mysqli_query($conn, $sql);
}
