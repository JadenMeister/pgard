<?php // corpus: expect=none
function find(Connection $connection, Request $request) {
    return $connection->executeQuery('SELECT * FROM users WHERE email = ?', [$request->get('email')])->fetchAllAssociative();
}
