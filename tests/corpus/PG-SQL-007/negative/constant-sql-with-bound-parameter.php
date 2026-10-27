<?php // corpus: expect=none
function find($conn) {
    $sql = 'SELECT * FROM users WHERE id = ?';
    $stmt = $conn->prepare($sql);
    $stmt->bind_param('i', $_GET['id']);
    $stmt->execute();
}
