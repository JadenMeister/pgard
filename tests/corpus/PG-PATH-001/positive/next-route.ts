// corpus: expect=PG-PATH-001
import { readFileSync } from "node:fs";
import { NextRequest } from "next/server";

export async function GET(request: NextRequest) {
  const name = request.nextUrl.searchParams.get("file")!;
  return new Response(readFileSync("public/reports/" + name));
}
