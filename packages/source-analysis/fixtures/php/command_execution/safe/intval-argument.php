<?php
function stop() {
    exec('kill -TERM ' . intval($_GET['pid']));
}
