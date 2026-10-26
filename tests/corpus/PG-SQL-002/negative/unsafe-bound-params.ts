// corpus: expect=none
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export async function byEmail(email: string) {
  return prisma.$queryRawUnsafe('SELECT * FROM "User" WHERE email = $1', email);
}
