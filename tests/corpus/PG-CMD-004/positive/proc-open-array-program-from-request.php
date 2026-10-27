<?php // corpus: expect=PG-CMD-004
function run() {
    proc_open([$_GET['tool'], '--version'], [], $pipes);
}
