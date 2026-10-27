<?php // corpus: expect=PG-CMD-004
function convert() {
    passthru(sprintf('convert %s out.png', $_GET['file']));
}
