<?php // corpus: expect=none
function find($conn) {
    return mysqli_query($conn, 'SELECT * FROM users WHERE id = ' . (int) $_GET['id']);
}
