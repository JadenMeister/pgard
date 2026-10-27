<?php // corpus: expect=none
function search(Request $request) {
    return User::whereRaw('lower(name) = ?', [strtolower($request->input('name'))])->get();
}
