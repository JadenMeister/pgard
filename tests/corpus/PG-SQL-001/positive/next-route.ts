// corpus: expect=PG-SQL-001
import { NextRequest, NextResponse } from "next/server";
import { Pool } from "pg";

const pool = new Pool();

export async function GET(request: NextRequest) {
  const id = request.nextUrl.searchParams.get("id");
  const result = await pool.query("SELECT * FROM invoices WHERE id = " + id);
  return NextResponse.json(result.rows);
}
