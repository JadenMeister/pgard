<?php // corpus: expect=PG-SQL-006
function dump($conn, $table) {
    return mysqli_query($conn, "SELECT * FROM " . $table);
}
