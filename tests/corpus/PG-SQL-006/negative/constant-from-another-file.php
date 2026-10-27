<?php // corpus: expect=low
function all($conn) {
    return mysqli_query($conn, 'SELECT * FROM ' . Schema::USERS_TABLE);
}
