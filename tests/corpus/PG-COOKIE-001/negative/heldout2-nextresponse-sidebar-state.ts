// corpus: expect=none
import { NextResponse } from "next/server";

export function POST() {
  const res = NextResponse.json({ ok: true });
  res.cookies.set("sidebar_state", "open", { path: "/" });
  return res;
}
