<?php // corpus: expect=none
function stop() {
    system('kill -TERM ' . (int) $_POST['pid']);
}
