<?php
function search(Request $request) {
    return User::whereRaw('email = ?', [$request->input('email')])->get();
}
