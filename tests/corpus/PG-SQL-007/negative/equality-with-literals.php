<?php // corpus: expect=low
function sorted($conn) {
    $dir = $_GET['dir'];
    if ($dir === 'asc' || $dir === 'desc') {
        return mysqli_query($conn, "SELECT * FROM users ORDER BY id $dir");
    }
}
