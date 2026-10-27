<?php // corpus: expect=PG-CMD-005
function run(string $command) {
    exec($command);
}
