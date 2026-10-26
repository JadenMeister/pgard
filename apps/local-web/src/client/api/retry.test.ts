import { afterEach, describe, expect, it, vi } from "vitest";
import { loadWithRetry } from "./retry";

afterEach(() => vi.useRealTimers());

describe("loadWithRetry", () => {
  it("gives up after three failed tries, waiting 1 s and 2 s", async () => {
    vi.useFakeTimers();
    const load = vi.fn(async () => {
      throw new Error("down");
    });
    const onSuccess = vi.fn();
    const onGiveUp = vi.fn();
    loadWithRetry(load, onSuccess, onGiveUp);
    await vi.advanceTimersByTimeAsync(0);
    expect(load).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1000);
    expect(load).toHaveBeenCalledTimes(2);
    expect(onGiveUp).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(2000);
    expect(load).toHaveBeenCalledTimes(3);
    expect(onGiveUp).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(10000);
    expect(load).toHaveBeenCalledTimes(3);
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it("stops at the first success", async () => {
    vi.useFakeTimers();
    const load = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(new Error("down"))
      .mockResolvedValueOnce("texts");
    const onSuccess = vi.fn();
    const onGiveUp = vi.fn();
    loadWithRetry(load, onSuccess, onGiveUp);
    await vi.advanceTimersByTimeAsync(5000);
    expect(onSuccess).toHaveBeenCalledWith("texts");
    expect(load).toHaveBeenCalledTimes(2);
    expect(onGiveUp).not.toHaveBeenCalled();
  });

  it("does nothing more after cancel", async () => {
    vi.useFakeTimers();
    const load = vi.fn(async () => {
      throw new Error("down");
    });
    const onGiveUp = vi.fn();
    const cancel = loadWithRetry(load, vi.fn(), onGiveUp);
    await vi.advanceTimersByTimeAsync(0);
    cancel();
    await vi.advanceTimersByTimeAsync(10000);
    expect(load).toHaveBeenCalledTimes(1);
    expect(onGiveUp).not.toHaveBeenCalled();
  });

  it("ignores a result that arrives after cancel", async () => {
    let resolve: (value: string) => void = () => undefined;
    const onSuccess = vi.fn();
    const cancel = loadWithRetry(
      () => new Promise<string>((r) => (resolve = r)),
      onSuccess,
      vi.fn(),
    );
    cancel();
    resolve("late");
    await Promise.resolve();
    expect(onSuccess).not.toHaveBeenCalled();
  });
});
