<?php // corpus: expect=PG-CMD-005
function archive($dir) {
    exec('tar czf backup.tgz ' . $dir);
}
