<?php // corpus: expect=PG-CMD-005
function convert() {
    passthru(sprintf('convert %s out.png', $_GET['file']));
}
