<?php // corpus: expect=PG-CMD-004
function listing() {
    system("ls -la {$_POST['dir']}");
}
