<?php // corpus: expect=low
function sorted($conn) {
    $columns = ['name' => 'users.name', 'date' => 'users.created_at'];
    $column = $columns[$_GET['sort']] ?? 'users.name';
    return mysqli_query($conn, "SELECT * FROM users ORDER BY $column");
}
