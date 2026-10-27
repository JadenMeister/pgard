<?php // corpus: expect=low
function find($conn) {
    return mysqli_query($conn, sprintf('SELECT * FROM users WHERE id = %d', $_GET['id']));
}
