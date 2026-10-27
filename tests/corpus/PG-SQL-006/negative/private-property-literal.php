<?php // corpus: expect=low
class Repo {
    private $table = 'users';

    public function all($conn) {
        return mysqli_query($conn, 'SELECT * FROM ' . $this->table);
    }
}
