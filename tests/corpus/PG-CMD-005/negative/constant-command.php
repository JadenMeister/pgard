<?php // corpus: expect=none
function disk() {
    return shell_exec('df -h /');
}
