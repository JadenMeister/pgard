// corpus: expect=none
import { cookies } from "next/headers";

export async function POST() {
  (await cookies()).set("theme", "dark", { path: "/" });
  return new Response(null, { status: 204 });
}
