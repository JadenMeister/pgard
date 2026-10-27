<?php // corpus: expect=none
function find($conn) {
    $name = $_GET['name'];
    $log = "searched for " . $name;
    error_log($log);
    return mysqli_query($conn, 'SELECT * FROM users');
}
