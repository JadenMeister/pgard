<?php // corpus: expect=PG-CMD-004
function whois() {
    return `whois {$_GET['domain']}`;
}
