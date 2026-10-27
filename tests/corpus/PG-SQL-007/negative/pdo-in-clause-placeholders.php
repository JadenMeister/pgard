<?php // corpus: expect=none
function find(PDO $pdo) {
    $ids = $_GET['ids'];
    $marks = implode(',', array_fill(0, count($ids), '?'));
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id IN ($marks)");
    $stmt->execute($ids);
    return $stmt->fetchAll();
}
