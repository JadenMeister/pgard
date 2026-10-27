<?php // corpus: expect=none
function recent() {
    return Post::selectRaw('count(*) as total')->orderByRaw('created_at desc')->havingRaw('total > 0')->get();
}
