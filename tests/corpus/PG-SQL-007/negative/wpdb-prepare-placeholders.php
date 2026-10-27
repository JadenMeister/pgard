<?php // corpus: expect=none
function find() {
    global $wpdb;
    return $wpdb->get_row($wpdb->prepare('SELECT * FROM wp_posts WHERE ID = %d', (int) $_GET['id']));
}
