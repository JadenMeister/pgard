<?php // corpus: expect=PG-SQL-007
function sorted($conn) {
    $dir = $_GET['dir'];
    abort_unless(in_array($dir, [$dir], true), 403);
    return mysqli_query($conn, "SELECT * FROM reports ORDER BY created_at " . $dir);
}
