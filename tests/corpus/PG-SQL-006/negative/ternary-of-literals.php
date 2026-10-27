<?php // corpus: expect=none
function sorted($conn) {
    $direction = $_GET['dir'] === 'desc' ? 'DESC' : 'ASC';
    return mysqli_query($conn, "SELECT * FROM users ORDER BY id $direction");
}
