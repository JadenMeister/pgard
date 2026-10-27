<?php
function byName(mysqli $conn) {
    $name = $_POST['name'];
    $sql = <<<SQL
        SELECT * FROM users WHERE name = '$name'
        SQL;
    return $conn->query($sql);
}
