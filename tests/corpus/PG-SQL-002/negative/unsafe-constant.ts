// corpus: expect=none
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export async function vacuum() {
  await prisma.$executeRawUnsafe("VACUUM ANALYZE");
}
