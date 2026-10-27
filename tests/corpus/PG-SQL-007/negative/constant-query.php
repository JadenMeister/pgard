<?php // corpus: expect=none
function all($conn) {
    return mysqli_query($conn, "SELECT * FROM users WHERE active = 1");
}
