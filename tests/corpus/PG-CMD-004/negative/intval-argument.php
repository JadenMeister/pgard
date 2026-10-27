<?php // corpus: expect=none
function stop() {
    exec('kill -TERM ' . intval($_GET['pid']));
}
