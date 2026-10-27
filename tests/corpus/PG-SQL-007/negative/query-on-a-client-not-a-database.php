<?php // corpus: expect=none
function search($client) {
    return $client->query($_GET['q']);
}
