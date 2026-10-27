<?php // corpus: expect=PG-CMD-005
function run() {
    $config = require 'config.php';
    system($config['command']);
}
