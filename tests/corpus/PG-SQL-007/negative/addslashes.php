<?php // corpus: expect=low
function find($conn) {
    return mysqli_query($conn, "SELECT * FROM users WHERE name = '" . addslashes($_GET['name']) . "'");
}
