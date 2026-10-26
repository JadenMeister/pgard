// corpus: expect=PG-AUTH-001
import { prisma } from "./db";

export async function signUp(email: string, password: string) {
  return prisma.user.create({ data: { email, password } });
}
