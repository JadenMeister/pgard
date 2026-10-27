<?php
function byName(mysqli $conn) {
    $stmt = $conn->prepare('SELECT * FROM users WHERE name = ?');
    $stmt->bind_param('s', $_GET['name']);
    $stmt->execute();
    return $stmt->get_result();
}
