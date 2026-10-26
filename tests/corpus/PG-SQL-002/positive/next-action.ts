// corpus: expect=PG-SQL-002
"use server";
import { prisma } from "@/lib/prisma";

export async function lookup(formData: FormData) {
  const term = formData.get("term") as string;
  const q = `SELECT * FROM "Post" WHERE title ILIKE '%${term}%'`;
  return prisma.$queryRawUnsafe(q);
}
