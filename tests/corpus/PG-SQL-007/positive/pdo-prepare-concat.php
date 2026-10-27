<?php // corpus: expect=PG-SQL-007
function find(PDO $pdo) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE name = '" . $_GET['name'] . "'");
    $stmt->execute();
    return $stmt->fetchAll();
}
