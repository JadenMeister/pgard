// corpus: expect=PG-SSRF-001
import { NextRequest } from "next/server";

export async function GET(request: NextRequest) {
  const url = request.nextUrl.searchParams.get("url")!;
  const res = await fetch(url);
  return new Response(res.body);
}
