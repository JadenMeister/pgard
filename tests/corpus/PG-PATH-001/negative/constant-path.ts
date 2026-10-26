// corpus: expect=none
import { readFileSync } from "node:fs";

export const LICENSE = readFileSync(new URL("../LICENSE", import.meta.url), "utf8");
