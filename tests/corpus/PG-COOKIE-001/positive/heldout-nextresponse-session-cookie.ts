// corpus: expect=PG-COOKIE-001
import { NextResponse } from "next/server";

export function POST() {
  const res = NextResponse.json({ ok: true });
  res.cookies.set("session", "abc", { path: "/" });
  return res;
}
