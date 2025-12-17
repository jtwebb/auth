import { auth } from './auth.js';

/**
 * Illustrative protected loader. Important part is returning the headers from requireUser(),
 * so session rotation Set-Cookie can propagate.
 */
export async function protectedLoader(request: Request) {
  const { userId, headers } = await auth.requireUser(request, { redirectTo: '/login' });
  return new Response(JSON.stringify({ userId }), {
    status: 200,
    headers
  });
}
