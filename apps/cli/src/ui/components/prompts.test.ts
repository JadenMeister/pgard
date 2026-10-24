import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { createCancelController } from "../../adapters/cancel.js";
import { scriptedKeys } from "../../test-support.js";
import { createStyle } from "../formatters/style.js";
import { BACK, promptChoice, promptConfirm, promptText, UserCancelledError } from "./prompts.js";

function context(keys: Parameters<typeof scriptedKeys>[0]) {
  return {
    keys: scriptedKeys(keys),
    out: new PassThrough(),
    style: createStyle(false),
    helpText: "help",
  };
}

const CTRL_C = { name: "c", sequence: "\u0003", ctrl: true };
const CHOICES = [
  { label: "A", value: "a" },
  { label: "B", value: "b" },
];

describe("promptChoice", () => {
  it("moves with arrows and selects with Enter", async () => {
    expect(await promptChoice(context(["down", "return"]), "Pick", CHOICES)).toBe("b");
    expect(await promptChoice(context(["up", "return"]), "Pick", CHOICES)).toBe("b");
  });

  it("returns BACK on Esc and shows help on ?", async () => {
    expect(await promptChoice(context(["?", "escape"]), "Pick", CHOICES)).toBe(BACK);
  });

  it("asks before cancelling on Ctrl+C", async () => {
    expect(await promptChoice(context([CTRL_C, "n", "return"]), "Pick", CHOICES)).toBe("a");
    await expect(promptChoice(context([CTRL_C, "y"]), "Pick", CHOICES)).rejects.toBeInstanceOf(
      UserCancelledError,
    );
  });
});

describe("promptConfirm", () => {
  it("only accepts an explicit y", async () => {
    expect(await promptConfirm(context(["y"]), "Ok?")).toBe(true);
    expect(await promptConfirm(context(["return"]), "Ok?")).toBe(false);
    expect(await promptConfirm(context(["n"]), "Ok?")).toBe(false);
    expect(await promptConfirm(context(["escape"]), "Ok?")).toBe(false);
    expect(await promptConfirm(context(["x", "1", "y"]), "Ok?")).toBe(true);
  });
});

describe("promptText", () => {
  it("collects printable characters, supports backspace and ignores control sequences", async () => {
    const keys = [
      "3",
      "0",
      "9",
      "backspace",
      "0",
      { name: "x", sequence: "\u001b[A", ctrl: false },
      "0",
      "return",
    ];
    expect(await promptText(context(keys), "Port:")).toBe("3000");
    expect(await promptText(context(["escape"]), "Port:")).toBe(BACK);
  });
});

describe("createCancelController", () => {
  it("aborts only on a second Ctrl+C within the window", () => {
    let listener: (() => void) | null = null;
    const messages: string[] = [];
    let clock = 0;
    const controller = createCancelController(
      { on: (_event, handler) => (listener = handler), off: () => (listener = null) },
      (message) => messages.push(message),
      () => clock,
    );
    listener!();
    expect(controller.signal.aborted).toBe(false);
    clock = 6000;
    listener!();
    expect(controller.signal.aborted).toBe(false);
    clock = 7000;
    listener!();
    expect(controller.signal.aborted).toBe(true);
    controller.dispose();
    expect(listener).toBeNull();
  });
});
