<?php // corpus: expect=low
function sorted($conn) {
    $dir = $_GET['dir'];
    abort_unless(in_array($dir, ['asc', 'desc']), 422);
    return mysqli_query($conn, "SELECT * FROM reports ORDER BY created_at " . $dir);
}
