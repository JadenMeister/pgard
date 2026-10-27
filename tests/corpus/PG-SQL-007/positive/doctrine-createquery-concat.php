<?php // corpus: expect=PG-SQL-007
function find($em, Request $request) {
    return $em->createQuery("SELECT u FROM App\\Entity\\User u WHERE u.name = '" . $request->query->get('name') . "'")->getResult();
}
