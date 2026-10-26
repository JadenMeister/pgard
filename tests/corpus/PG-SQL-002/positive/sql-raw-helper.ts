// corpus: expect=PG-SQL-002
import { Prisma, PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export async function byCol(col: string, value: string) {
  // Prisma.raw splices the text into the statement as-is.
  return prisma.$queryRaw(Prisma.sql`SELECT * FROM "User" WHERE ${Prisma.raw(col)} = ${value}`);
}
