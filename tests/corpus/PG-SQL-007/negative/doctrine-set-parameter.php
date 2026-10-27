<?php // corpus: expect=none
function find($em, Request $request) {
    return $em->createQuery('SELECT u FROM App\\Entity\\User u WHERE u.name = :name')
        ->setParameter('name', $request->query->get('name'))
        ->getResult();
}
