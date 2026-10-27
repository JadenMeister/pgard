<?php // corpus: expect=PG-SQL-007
function sorted(PDO $pdo) {
    $column = $_GET['sort'];
    $stmt = $pdo->prepare("SELECT * FROM users ORDER BY $column");
    $stmt->execute();
    return $stmt->fetchAll();
}
