// corpus: expect=none
import bcrypt from "bcrypt";
import { prisma } from "./db";

export async function signUp(email: string, password: string) {
  const hashed = await bcrypt.hash(password, 12);
  return prisma.user.create({ data: { email, password: hashed } });
}
