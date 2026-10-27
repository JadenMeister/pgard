<?php // corpus: expect=low
function build() {
    $target = $_GET['target'];
    if (in_array($target, ['dev', 'prod'], true)) {
        system("make $target");
    }
}
