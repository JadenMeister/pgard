<?php // corpus: expect=PG-SQL-007
function search() {
    global $wpdb;
    return $wpdb->get_results("SELECT * FROM {$wpdb->prefix}posts WHERE post_title = '" . $_GET['title'] . "'");
}
