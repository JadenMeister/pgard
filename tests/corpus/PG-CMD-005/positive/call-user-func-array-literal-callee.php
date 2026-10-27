<?php // corpus: expect=PG-CMD-005
function run() {
    return call_user_func_array('exec', ['ls ' . $_GET['dir']]);
}
