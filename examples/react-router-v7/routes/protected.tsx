import * as React from 'react';

/**
 * Illustrative protected page. The server-side loader should require auth.
 * See `examples/react-router-v7/server/protected-loader.ts`.
 */
export function ProtectedRoute(props: { userId: string }) {
  return (
    <div>
      <h1>Protected</h1>
      <p>Signed in as: {props.userId}</p>
    </div>
  );
}
