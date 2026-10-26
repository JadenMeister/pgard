// corpus: expect=PG-SQL-002; known=miss:PG-SQL-002:Prisma.raw() spliced into a Prisma.sql template is not recognised as unsafe
import { Prisma, PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export async function byCol(col: string, value: string) {
  // Prisma.raw splices the text into the statement as-is.
  return prisma.$queryRaw(Prisma.sql`SELECT * FROM "User" WHERE ${Prisma.raw(col)} = ${value}`);
}
