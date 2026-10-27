<?php // corpus: expect=low
function sorted($conn) {
    $column = $_GET['sort'];
    if (!in_array($column, ['name', 'email', 'created_at'], true)) {
        return [];
    }
    return mysqli_query($conn, "SELECT * FROM users ORDER BY $column");
}
