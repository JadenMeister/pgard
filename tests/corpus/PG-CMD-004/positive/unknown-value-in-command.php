<?php // corpus: expect=PG-CMD-004
function archive($dir) {
    exec('tar czf backup.tgz ' . $dir);
}
