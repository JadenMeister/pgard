<?php // corpus: expect=low
function sorted($conn) {
    $column = $_GET['sort'];
    if (!preg_match('/^[a-z_]+$/', $column)) {
        exit;
    }
    return mysqli_query($conn, "SELECT * FROM users ORDER BY $column");
}
