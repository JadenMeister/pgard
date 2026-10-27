<?php // corpus: expect=PG-SQL-007
function find(PDO $pdo) {
    return $pdo->query("SELECT * FROM users WHERE name = '" . $_GET['name'] . "'")->fetchAll();
}
