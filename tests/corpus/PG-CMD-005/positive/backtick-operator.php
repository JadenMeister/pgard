<?php // corpus: expect=PG-CMD-005
function whois() {
    return `whois {$_GET['domain']}`;
}
