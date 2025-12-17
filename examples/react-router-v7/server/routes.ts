import { auth } from './auth.js';

/**
 * Illustrative endpoint handlers. In a real React Router v7 app these would typically be
 * actions/loaders, or server endpoints depending on your deployment.
 */
export const routes = {
  async postLogin(request: Request) {
    return await auth.actions.passwordLogin(request, { redirectTo: '/' });
  },

  async postRegister(request: Request) {
    return await auth.actions.passwordRegister(request, { redirectTo: '/' });
  },

  async postLogout(request: Request) {
    return await auth.logout(request, { redirectTo: '/login' });
  },

  async postPasskeyRegisterStart(request: Request) {
    return await auth.actions.passkeyRegistrationStart(request);
  },

  async postPasskeyRegisterFinish(request: Request) {
    return await auth.actions.passkeyRegistrationFinish(request, { redirectTo: '/' });
  },

  async postPasskeyLoginStart(request: Request) {
    return await auth.actions.passkeyLoginStart(request);
  },

  async postPasskeyLoginFinish(request: Request) {
    return await auth.actions.passkeyLoginFinish(request, { redirectTo: '/' });
  }
};
