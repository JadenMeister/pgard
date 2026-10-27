<?php // corpus: expect=PG-SQL-006
function find(mysqli $mysqli) {
    return $mysqli->query("SELECT * FROM users WHERE email = '" . $_REQUEST['email'] . "'");
}
