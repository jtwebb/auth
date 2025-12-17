import * as React from "react";
import { LoginForm, PasskeyLoginButton } from "../../../src/react/index.js";

export function LoginRoute() {
  return (
    <div>
      <h1>Sign in</h1>

      <LoginForm
        onSubmit={async ({ identifier, password }) => {
          // Your RR action would typically handle this. This is just illustrative.
          const res = await fetch("/api/auth/login", {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ identifier, password }),
            credentials: "include",
          });
          if (!res.ok) throw new Error("Login failed");
        }}
      />

      <hr />

      <PasskeyLoginButton
        loginStartUrl="/api/passkeys/login/start"
        loginFinishUrl="/api/passkeys/login/finish"
        onSuccess={() => {
          window.location.assign("/");
        }}
      />
    </div>
  );
}


