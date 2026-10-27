<?php // corpus: expect=PG-SQL-006
function find(Connection $connection, Request $request) {
    return $connection->executeQuery("SELECT * FROM users WHERE email = '" . $request->get('email') . "'")->fetchAllAssociative();
}
