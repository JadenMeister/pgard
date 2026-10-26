// corpus: expect=PG-SQL-002
import { Prisma, PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export function sortedPosts(sortCol: string, limit: number) {
  return prisma.$queryRaw(Prisma.sql`SELECT * FROM "Post" ORDER BY ${Prisma.raw(sortCol)} LIMIT ${limit}`);
}
