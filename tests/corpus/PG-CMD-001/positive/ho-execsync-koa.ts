// corpus: expect=PG-CMD-001
import { execSync } from "node:child_process";

export function listing(ctx: any) {
  ctx.body = execSync(`ls -la ${ctx.query.dir}`).toString();
}
