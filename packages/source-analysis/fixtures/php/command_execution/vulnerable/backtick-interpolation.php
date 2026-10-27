<?php
function lookup() {
    return `nslookup {$_GET['host']}`;
}
