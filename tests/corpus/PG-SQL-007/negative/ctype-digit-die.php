<?php // corpus: expect=low
function find($conn) {
    $id = $_GET['id'];
    if (!ctype_digit($id)) {
        die('bad id');
    }
    return mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
}
