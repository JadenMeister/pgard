<?php // corpus: expect=PG-CMD-005
function listing() {
    system("ls -la {$_POST['dir']}");
}
