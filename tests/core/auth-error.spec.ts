import { describe, expect, it } from "vitest";
import { AuthError, defaultStatusForCode, isAuthError } from "../../src/core/auth-error.js";

describe("core/auth-error", () => {
  it("creates an AuthError with code + default status", () => {
    const err = new AuthError("invalid_input", "bad");
    expect(err.code).toBe("invalid_input");
    expect(err.status).toBe(400);
    expect(isAuthError(err)).toBe(true);
  });

  it("maps defaultStatusForCode correctly for a few key codes", () => {
    expect(defaultStatusForCode("unauthorized")).toBe(401);
    expect(defaultStatusForCode("rate_limited")).toBe(429);
    expect(defaultStatusForCode("not_implemented")).toBe(501);
  });
});


