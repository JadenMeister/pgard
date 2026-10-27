<?php // corpus: expect=low
function published() {
    global $wpdb;
    return $wpdb->get_results("SELECT * FROM {$wpdb->prefix}posts WHERE post_status = 'publish'");
}
