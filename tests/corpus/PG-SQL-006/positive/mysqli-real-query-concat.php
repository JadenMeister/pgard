<?php // corpus: expect=PG-SQL-006
function purge($mysqli) {
    $mysqli->real_query("DELETE FROM sessions WHERE token = '" . $_COOKIE['token'] . "'");
}
