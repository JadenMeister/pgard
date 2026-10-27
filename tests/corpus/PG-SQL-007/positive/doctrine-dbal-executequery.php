<?php // corpus: expect=PG-SQL-007
function find(Connection $connection, Request $request) {
    return $connection->executeQuery("SELECT * FROM users WHERE email = '" . $request->get('email') . "'")->fetchAllAssociative();
}
