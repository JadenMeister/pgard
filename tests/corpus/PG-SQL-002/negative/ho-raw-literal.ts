// corpus: expect=none
import { Prisma, PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export function newest(limit: number) {
  return prisma.$queryRaw(Prisma.sql`SELECT * FROM "Post" ORDER BY "createdAt" ${Prisma.raw("DESC")} LIMIT ${limit}`);
}
