<?php // corpus: expect=PG-SQL-007
function find(mysqli $mysqli) {
    return $mysqli->query("SELECT * FROM users WHERE email = '" . $_REQUEST['email'] . "'");
}
