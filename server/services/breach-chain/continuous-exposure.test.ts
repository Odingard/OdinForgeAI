import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { computeNextRunAt, type ChainScheduleConfig } from "./continuous-exposure";

describe("computeNextRunAt", () => {
  beforeEach(() => {
    // Fix date to 2026-03-12T10:00:00Z (Thursday)
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-12T10:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("daily schedule returns next day at specified time if past today's time", () => {
    const config: ChainScheduleConfig = { enabled: true, frequency: "daily", timeOfDay: "02:00" };
    const next = computeNextRunAt(config);

    // 02:00 is before 10:00, so should be tomorrow
    expect(next.getDate()).toBe(13);
    expect(next.getHours()).toBe(2);
    expect(next.getMinutes()).toBe(0);
  });

  it("daily schedule returns today if time hasn't passed yet", () => {
    const config: ChainScheduleConfig = { enabled: true, frequency: "daily", timeOfDay: "22:00" };
    const next = computeNextRunAt(config);

    expect(next.getDate()).toBe(12); // today
    expect(next.getHours()).toBe(22);
  });

  it("weekly schedule returns next occurrence of target day", () => {
    // March 12, 2026 is Thursday (day 4). Target Monday (day 1).
    const config: ChainScheduleConfig = { enabled: true, frequency: "weekly", dayOfWeek: 1, timeOfDay: "03:00" };
    const next = computeNextRunAt(config);

    // Next Monday from Thursday = 3 days later = March 16
    expect(next.getDay()).toBe(1); // Monday
    expect(next.getDate()).toBe(16);
  });

  it("weekly schedule defaults to Monday if dayOfWeek not set", () => {
    const config: ChainScheduleConfig = { enabled: true, frequency: "weekly", timeOfDay: "03:00" };
    const next = computeNextRunAt(config);

    expect(next.getDay()).toBe(1); // Monday
  });

  it("monthly schedule returns first of next month if past this month", () => {
    const config: ChainScheduleConfig = { enabled: true, frequency: "monthly", timeOfDay: "04:00" };
    const next = computeNextRunAt(config);

    // March 12 at 10:00, first of March at 04:00 is past
    expect(next.getMonth()).toBe(3); // April (0-indexed)
    expect(next.getDate()).toBe(1);
  });

  it("manual schedule returns far future date", () => {
    const config: ChainScheduleConfig = { enabled: true, frequency: "manual" };
    const next = computeNextRunAt(config);

    expect(next.getFullYear()).toBe(9999);
  });

  it("defaults timeOfDay to 02:00 if not specified", () => {
    const config: ChainScheduleConfig = { enabled: true, frequency: "daily" };
    const next = computeNextRunAt(config);

    expect(next.getHours()).toBe(2);
    expect(next.getMinutes()).toBe(0);
  });
});
