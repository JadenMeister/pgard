<?php
function byId(PDO $pdo) {
    return $pdo->query("SELECT * FROM users WHERE id = {$_GET['id']}")->fetchAll();
}
