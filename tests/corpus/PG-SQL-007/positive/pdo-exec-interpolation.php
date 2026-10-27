<?php // corpus: expect=PG-SQL-007
class Repo {
    public function __construct(private PDO $pdo) {}

    public function remove(Request $request): int {
        return $this->pdo->exec("DELETE FROM posts WHERE id = {$request->input('id')}");
    }
}
