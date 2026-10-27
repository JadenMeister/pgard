<?php // corpus: expect=low
function find($conn) {
    foreach ($_GET['ids'] as $id) {
        if (!is_numeric($id)) {
            continue;
        }
        mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
    }
}
