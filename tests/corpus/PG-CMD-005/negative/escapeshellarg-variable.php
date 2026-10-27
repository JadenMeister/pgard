<?php // corpus: expect=low
function convert() {
    $file = escapeshellarg($_GET['file']);
    shell_exec("convert $file out.png");
}
