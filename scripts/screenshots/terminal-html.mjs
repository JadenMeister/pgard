// ANSI text -> a page that looks like a terminal window (dark background, monospace font, a
// title bar). Every non-ASCII character is put in a box exactly one or two cells wide, so
// Korean text and box-drawing characters stay on the terminal grid whatever font Chrome picks.
const PALETTE = [
  "#1f2229",
  "#e06c75",
  "#98c379",
  "#e5c07b",
  "#61afef",
  "#c678dd",
  "#56b6c2",
  "#abb2bf",
  "#5c6370",
  "#ff7b86",
  "#a9d98a",
  "#f0cf8e",
  "#7bbcff",
  "#d58cf0",
  "#6fcbd6",
  "#ffffff",
];
const DEFAULT_FG = "#d7dae0";
const DEFAULT_BG = "#16181d";

function xterm256(n) {
  if (n < 16) return PALETTE[n];
  if (n >= 232) {
    const v = 8 + (n - 232) * 10;
    return `rgb(${v},${v},${v})`;
  }
  const i = n - 16;
  const level = (c) => (c === 0 ? 0 : 55 + c * 40);
  return `rgb(${level(Math.floor(i / 36))},${level(Math.floor(i / 6) % 6)},${level(i % 6)})`;
}

const escapeHtml = (text) =>
  text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");

/** Cell width of one character: 2 for East Asian wide characters, else 1. */
function cells(char) {
  const code = char.codePointAt(0);
  const isWide =
    (code >= 0x1100 && code <= 0x115f) ||
    (code >= 0x2e80 && code <= 0xa4cf) ||
    (code >= 0xac00 && code <= 0xd7a3) ||
    (code >= 0xf900 && code <= 0xfaff) ||
    (code >= 0xfe30 && code <= 0xfe6f) ||
    (code >= 0xff00 && code <= 0xff60) ||
    (code >= 0xffe0 && code <= 0xffe6);
  return isWide ? 2 : 1;
}

function line(text) {
  let state = {};
  let html = "";
  const open = () => {
    const style = [];
    let fg = state.fg;
    let bg = state.bg;
    if (state.reverse) [fg, bg] = [bg ?? DEFAULT_BG, fg ?? DEFAULT_FG];
    if (fg) style.push(`color:${fg}`);
    if (bg) style.push(`background:${bg}`);
    if (state.bold) style.push("font-weight:700");
    if (state.dim) style.push("opacity:.62");
    if (state.italic) style.push("font-style:italic");
    if (state.underline) style.push("text-decoration:underline");
    return style.length > 0 ? `<span style="${style.join(";")}">` : "<span>";
  };
  let buffer = "";
  const flush = () => {
    if (buffer !== "") html += `${open()}${buffer}</span>`;
    buffer = "";
  };
  const parts = text.split(/\u001b\[([0-9;]*)m/);
  for (let i = 0; i < parts.length; i += 1) {
    if (i % 2 === 0) {
      for (const char of parts[i]) {
        if (char.charCodeAt(0) < 128) buffer += escapeHtml(char);
        else buffer += `<i class="w${cells(char)}">${char}</i>`;
      }
      continue;
    }
    flush();
    const codes = parts[i] === "" ? [0] : parts[i].split(";").map(Number);
    for (let c = 0; c < codes.length; c += 1) {
      const code = codes[c];
      if (code === 0) state = {};
      else if (code === 1) state.bold = true;
      else if (code === 2) state.dim = true;
      else if (code === 3) state.italic = true;
      else if (code === 4) state.underline = true;
      else if (code === 7) state.reverse = true;
      else if (code === 22) state.bold = state.dim = false;
      else if (code === 23) state.italic = false;
      else if (code === 24) state.underline = false;
      else if (code === 27) state.reverse = false;
      else if (code >= 30 && code <= 37) state.fg = PALETTE[code - 30];
      else if (code >= 90 && code <= 97) state.fg = PALETTE[code - 90 + 8];
      else if (code >= 40 && code <= 47) state.bg = PALETTE[code - 40];
      else if (code >= 100 && code <= 107) state.bg = PALETTE[code - 100 + 8];
      else if (code === 39) state.fg = undefined;
      else if (code === 49) state.bg = undefined;
      else if (code === 38 || code === 48) {
        const key = code === 38 ? "fg" : "bg";
        if (codes[c + 1] === 5) {
          state[key] = xterm256(codes[c + 2]);
          c += 2;
        } else if (codes[c + 1] === 2) {
          state[key] = `rgb(${codes[c + 2]},${codes[c + 3]},${codes[c + 4]})`;
          c += 4;
        }
      }
    }
  }
  flush();
  return html;
}

/** A full HTML page: a terminal window of `columns` x `lines.length` cells. */
export function terminalPage(lines, { columns, title, fontSize = 15 }) {
  const body = lines.map(line).join("\n");
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title>
<style>
  html, body { margin: 0; background: #0d0e11; }
  body { padding: 28px 32px 36px; display: flex; justify-content: center; }
  .window { border-radius: 12px; overflow: hidden; background: ${DEFAULT_BG};
    box-shadow: 0 18px 50px rgba(0,0,0,.55), 0 0 0 1px #2c2f38; }
  .bar { height: 36px; display: flex; align-items: center; gap: 8px; padding: 0 14px;
    background: #23262d; border-bottom: 1px solid #14161a; position: relative; }
  .bar b { width: 12px; height: 12px; border-radius: 50%; display: block; }
  .bar b:nth-child(1) { background: #ff5f57; } .bar b:nth-child(2) { background: #febc2e; }
  .bar b:nth-child(3) { background: #28c840; }
  .bar span { position: absolute; left: 0; right: 0; text-align: center; color: #9aa0ab;
    font: 13px -apple-system, "Helvetica Neue", Arial, sans-serif; pointer-events: none; }
  pre { margin: 0; padding: 14px 18px 16px; color: ${DEFAULT_FG}; background: ${DEFAULT_BG};
    font: ${fontSize}px/1.32 Menlo, "SF Mono", "DejaVu Sans Mono", Consolas, monospace;
    font-variant-ligatures: none; width: ${columns}ch; white-space: pre; }
  pre i { font-style: normal; display: inline-block; text-align: center; overflow: visible; }
  pre i.w1 { width: 1ch; }
  pre i.w2 { width: 2ch;
    font-family: "Apple SD Gothic Neo", "Noto Sans CJK KR", "Malgun Gothic", Menlo, monospace; }
</style></head><body>
<div class="window"><div class="bar"><b></b><b></b><b></b><span>${escapeHtml(title)}</span></div>
<pre>${body}</pre></div></body></html>`;
}
