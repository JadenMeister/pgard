<?php // corpus: expect=none
function sorted($conn) {
    $direction = match ($_GET['dir'] ?? '') {
        'desc' => 'DESC',
        default => 'ASC',
    };
    return mysqli_query($conn, "SELECT * FROM users ORDER BY id $direction");
}
