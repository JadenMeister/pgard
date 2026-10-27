<?php // corpus: expect=none
function find(PDO $pdo) {
    $stmt = $pdo->prepare('SELECT * FROM users WHERE name = ? AND age > ?');
    $stmt->bindValue(1, $_GET['name']);
    $stmt->bindValue(2, $_GET['age'], PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll();
}
