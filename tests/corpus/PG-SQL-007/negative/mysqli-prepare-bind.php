<?php // corpus: expect=none
function find(mysqli $mysqli) {
    $stmt = $mysqli->prepare('SELECT * FROM users WHERE name = ?');
    $stmt->bind_param('s', $_GET['name']);
    $stmt->execute();
    return $stmt->get_result();
}
