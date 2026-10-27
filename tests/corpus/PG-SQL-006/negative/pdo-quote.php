<?php // corpus: expect=low
function find(PDO $pdo) {
    $name = $pdo->quote($_GET['name']);
    return $pdo->query("SELECT * FROM users WHERE name = $name")->fetchAll();
}
