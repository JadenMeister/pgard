<?php
function disk() {
    return shell_exec('df -h /');
}
