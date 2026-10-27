<?php // corpus: expect=none
function run($conn, string $sql) {
    return mysqli_query($conn, $sql);
}
