<?php // corpus: expect=low
function ping() {
    exec('ping -c 1 ' . escapeshellarg($_GET['host']));
}
