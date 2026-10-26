// corpus: expect=none
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export async function search(name: string) {
  return prisma.$queryRaw`SELECT * FROM "User" WHERE name = ${name}`;
}
