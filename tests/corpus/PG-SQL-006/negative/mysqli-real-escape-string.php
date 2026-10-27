<?php // corpus: expect=low
function find($conn) {
    $name = mysqli_real_escape_string($conn, $_GET['name']);
    return mysqli_query($conn, "SELECT * FROM users WHERE name = '$name'");
}
