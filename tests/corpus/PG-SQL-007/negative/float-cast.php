<?php // corpus: expect=none
function near($conn) {
    $lat = (float) $_GET['lat'];
    return mysqli_query($conn, "SELECT * FROM places WHERE lat > $lat");
}
