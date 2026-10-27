<?php
function byName(mysqli $conn) {
    return mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $_GET['name'] . "'");
}
