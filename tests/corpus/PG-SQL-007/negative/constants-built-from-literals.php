<?php // corpus: expect=none
const TABLE = 'users';
define('ORDER', 'created_at DESC');

class Cols {
    const NAME = 'name';
    const PAIR = self::NAME . ', email';
}

function all($conn) {
    return mysqli_query($conn, 'SELECT ' . Cols::PAIR . ' FROM ' . TABLE . ' ORDER BY ' . ORDER);
}
