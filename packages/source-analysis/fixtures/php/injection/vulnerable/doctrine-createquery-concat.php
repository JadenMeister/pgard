<?php
function byName($em, Request $request) {
    return $em->createQuery("SELECT u FROM User u WHERE u.name = '" . $request->query->get('name') . "'")->getResult();
}
