<?php // corpus: expect=none
function search(Request $request) {
    return User::where('name', $request->input('name'))->orderBy('id')->get();
}
