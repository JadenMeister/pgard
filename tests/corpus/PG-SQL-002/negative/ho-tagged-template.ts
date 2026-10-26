// corpus: expect=none
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export async function byId(req: any) {
  const id = Number(req.params.id);
  return prisma.$queryRaw`SELECT * FROM "User" WHERE id = ${id}`;
}
