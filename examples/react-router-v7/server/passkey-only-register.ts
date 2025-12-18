import { core } from './auth.js';
import { storage } from './auth.js';

/**
 * Passkey-only signup pattern (illustrative):
 * 1) Create the user record (no password credential)
 * 2) Start passkey registration for that user
 * 3) Finish passkey registration with browser response
 *
 * You would typically split start/finish into separate HTTP endpoints.
 */
export async function startPasskeyOnlyRegistration(input: {
  identifier: string;
  displayName?: string;
}) {
  const userId = await storage.users.createUser(input.identifier);

  return await core.startPasskeyRegistration({
    userId,
    userName: input.identifier,
    userDisplayName: input.displayName ?? input.identifier
  });
}
