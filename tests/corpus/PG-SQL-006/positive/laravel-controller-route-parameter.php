<?php // corpus: expect=PG-SQL-006
namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;

class UserController extends Controller {
    public function show($id) {
        return DB::select("SELECT * FROM users WHERE id = $id");
    }
}
