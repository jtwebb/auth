import { describe, expect, it, vi } from "vitest";
import { createPasskeyFlows } from "../../src/react/passkey-flows.js";

describe("react/passkey-flows", () => {
  it("login flow calls start->browser->finish in order", async () => {
    const calls: string[] = [];
    const fetchFn = vi.fn(async (url: any, init: any) => {
      calls.push(String(url));
      const body = init?.body ? JSON.parse(init.body) : null;
      if (String(url).endsWith("/login/start")) {
        return new Response(JSON.stringify({ challengeId: "c1", options: { challenge: "x" } }), { status: 200 });
      }
      if (String(url).endsWith("/login/finish")) {
        expect(body.challengeId).toBe("c1");
        expect(body.response).toEqual({ id: "cred-1" });
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
      return new Response("not found", { status: 404 });
    });

    const startAuthenticationFn = vi.fn(async () => ({ id: "cred-1" } as any));

    const flows = createPasskeyFlows(
      {
        registrationStartUrl: "/reg/start",
        registrationFinishUrl: "/reg/finish",
        loginStartUrl: "/login/start",
        loginFinishUrl: "/login/finish",
      },
      { fetchFn, startAuthenticationFn, startRegistrationFn: vi.fn() as any },
    );

    await flows.login();
    expect(fetchFn).toHaveBeenCalledTimes(2);
    expect(calls).toEqual(["/login/start", "/login/finish"]);
    expect(startAuthenticationFn).toHaveBeenCalledTimes(1);
  });
});


