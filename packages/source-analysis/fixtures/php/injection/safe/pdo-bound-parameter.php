<?php
function byId(PDO $pdo) {
    $stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
    $stmt->execute(['id' => $_GET['id']]);
    return $stmt->fetchAll();
}
