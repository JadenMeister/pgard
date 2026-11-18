<?php // corpus: expect=none
function search($em) {
    $qb = $em->createQueryBuilder();
    $qb->select('u')->from('App\Entity\User', 'u');
    $qb->where('u.name = :name')->setParameter('name', $_GET['name']);
    $qb->andWhere($qb->expr()->eq('u.role', ':role'))->setParameter('role', 'admin');
    return $qb->getQuery()->getResult();
}
