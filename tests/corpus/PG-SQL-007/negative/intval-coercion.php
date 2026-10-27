<?php // corpus: expect=none
function find($conn) {
    $id = intval($_GET['id']);
    return mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
}
