<?php // corpus: expect=none
function find(PDO $pdo) {
    $stmt = $pdo->prepare('SELECT * FROM users WHERE name = :name');
    $stmt->execute(['name' => $_GET['name']]);
    return $stmt->fetchAll();
}
