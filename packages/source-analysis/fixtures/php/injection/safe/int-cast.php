<?php
function byId(mysqli $conn) {
    $id = (int) $_GET['id'];
    return $conn->query("SELECT * FROM users WHERE id = $id");
}
