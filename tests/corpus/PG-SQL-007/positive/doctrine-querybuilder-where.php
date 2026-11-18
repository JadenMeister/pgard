<?php // corpus: expect=PG-SQL-007
function search($em) {
    $qb = $em->createQueryBuilder();
    $qb->select('u')->from('App\Entity\User', 'u');
    $qb->where("u.name = '" . $_GET['name'] . "'");
    return $qb->getQuery()->getResult();
}
