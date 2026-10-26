// corpus: expect=none
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export async function search(name: string) {
  return prisma.user.findMany({ where: { name: { contains: name } } });
}
