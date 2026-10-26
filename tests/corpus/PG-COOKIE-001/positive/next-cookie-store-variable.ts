// corpus: expect=PG-COOKIE-001
import { cookies } from "next/headers";

export async function POST() {
  const store = await cookies();
  store.set({ name: "session", value: "abc", path: "/" });
  return new Response(null, { status: 204 });
}
