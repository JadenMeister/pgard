<?php // corpus: expect=PG-SQL-007
function dump($conn, $table) {
    return mysqli_query($conn, "SELECT * FROM " . $table);
}
