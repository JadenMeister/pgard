// A small terminal-screen model for the pty smoke test: enough of VT100/xterm to replay what the
// panel view (and the Windows ConPTY layer in front of it) writes, so the test can look at the
// resulting screen instead of at raw bytes. Test-only; not part of the CLI.
import { displayWidth } from "../../apps/cli/dist/ui/i18n/display-width.js";

export class Screen {
  constructor(columns, rows) {
    this.columns = columns;
    this.rows = rows;
    /** Count of printable characters that did not fit on their line (the terminal wrapped them). */
    this.overflow = 0;
    /** Private-mode switches in order: `{ mode: 1049, on: true, at: <byte offset> }`. */
    this.modes = [];
    this.title = null;
    this.state = "text";
    this.buffer = "";
    this.clear();
  }

  clear() {
    this.cells = Array.from({ length: this.rows }, () => Array(this.columns).fill(" "));
    this.x = 0;
    this.y = 0;
  }

  /** Like a terminal resize followed by the application's full redraw: start from a clean screen. */
  resize(columns, rows) {
    this.columns = columns;
    this.rows = rows;
    this.clear();
    this.overflow = 0;
  }

  lines() {
    return this.cells.map((row) => row.join("").replace(/\s+$/u, ""));
  }

  text() {
    return this.lines().join("\n");
  }

  lineFeed() {
    if (this.y + 1 >= this.rows) {
      this.cells.shift();
      this.cells.push(Array(this.columns).fill(" "));
    } else {
      this.y += 1;
    }
  }

  put(char) {
    const width = displayWidth(char);
    if (width === 0) return;
    if (this.x + width > this.columns) {
      this.overflow += 1;
      this.x = 0;
      this.lineFeed();
    }
    this.cells[this.y][this.x] = char;
    if (width === 2 && this.x + 1 < this.columns) this.cells[this.y][this.x + 1] = "";
    this.x += width;
  }

  feed(data, offset = 0) {
    for (const char of data) this.step(char, offset);
  }

  step(char, offset) {
    switch (this.state) {
      case "text":
        if (char === "\u001b") this.state = "esc";
        else if (char === "\r") this.x = 0;
        else if (char === "\n") this.lineFeed();
        else if (char === "\b") this.x = Math.max(0, this.x - 1);
        else if (char === "\t")
          this.x = Math.min(this.columns - 1, (Math.floor(this.x / 8) + 1) * 8);
        else if (char >= " " && !(char >= "\u007f" && char <= "\u009f")) this.put(char);
        return;
      case "esc":
        this.buffer = "";
        if (char === "[") this.state = "csi";
        else if (char === "]") this.state = "osc";
        else if (char === "(" || char === ")" || char === "#") this.state = "skip1";
        else this.state = "text";
        return;
      case "skip1":
        this.state = "text";
        return;
      case "csi":
        if (char >= "@" && char <= "~") {
          this.csi(this.buffer, char, offset);
          this.state = "text";
        } else {
          this.buffer += char;
        }
        return;
      case "osc":
        if (char === "\u0007") {
          this.osc(this.buffer);
          this.state = "text";
        } else if (char === "\u001b") {
          this.state = "oscEnd";
        } else {
          this.buffer += char;
        }
        return;
      case "oscEnd":
        this.osc(this.buffer);
        this.state = char === "\\" ? "text" : "esc";
        if (this.state === "esc") this.step(char, offset);
        return;
    }
  }

  osc(body) {
    if (/^[02];/u.test(body)) this.title = body.slice(2);
  }

  csi(raw, final, offset) {
    const isPrivate = raw.startsWith("?");
    const params = raw
      .replace(/^[?>=!]/u, "")
      .split(";")
      .map((part) => (part === "" ? null : Number(part)));
    const first = (fallback) =>
      params[0] === null || params[0] === undefined ? fallback : params[0];
    const clampX = (x) => Math.min(Math.max(x, 0), this.columns - 1);
    const clampY = (y) => Math.min(Math.max(y, 0), this.rows - 1);
    switch (final) {
      case "H":
      case "f":
        this.y = clampY(first(1) - 1);
        this.x = clampX((params[1] ?? 1) - 1);
        return;
      case "A":
        this.y = clampY(this.y - Math.max(1, first(1)));
        return;
      case "B":
        this.y = clampY(this.y + Math.max(1, first(1)));
        return;
      case "C":
        this.x = clampX(this.x + Math.max(1, first(1)));
        return;
      case "D":
        this.x = clampX(this.x - Math.max(1, first(1)));
        return;
      case "G":
        this.x = clampX(first(1) - 1);
        return;
      case "d":
        this.y = clampY(first(1) - 1);
        return;
      case "J": {
        const mode = first(0);
        if (mode === 2 || mode === 3)
          this.cells = this.cells.map(() => Array(this.columns).fill(" "));
        else if (mode === 0) {
          this.cells[this.y].fill(" ", this.x);
          for (let row = this.y + 1; row < this.rows; row += 1) this.cells[row].fill(" ");
        } else if (mode === 1) {
          this.cells[this.y].fill(" ", 0, this.x + 1);
          for (let row = 0; row < this.y; row += 1) this.cells[row].fill(" ");
        }
        return;
      }
      case "K": {
        const mode = first(0);
        if (mode === 0) this.cells[this.y].fill(" ", this.x);
        else if (mode === 1) this.cells[this.y].fill(" ", 0, this.x + 1);
        else this.cells[this.y].fill(" ");
        return;
      }
      case "X":
        this.cells[this.y].fill(" ", this.x, this.x + Math.max(1, first(1)));
        return;
      case "h":
      case "l":
        if (isPrivate) {
          for (const mode of params) {
            if (mode === null) continue;
            this.modes.push({ mode, on: final === "h", at: offset });
            if (mode === 1049 && final === "h") this.clear();
          }
        }
        return;
      default:
        return;
    }
  }
}
