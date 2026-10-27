<?php // corpus: expect=none
const BIN = '/usr/bin/git';

class Cmd {
    const LOG = BIN . ' log --oneline';
}

function history() {
    return shell_exec(Cmd::LOG . ' -n 5');
}
