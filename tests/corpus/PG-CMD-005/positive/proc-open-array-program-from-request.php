<?php // corpus: expect=PG-CMD-005
function run() {
    proc_open([$_GET['tool'], '--version'], [], $pipes);
}
