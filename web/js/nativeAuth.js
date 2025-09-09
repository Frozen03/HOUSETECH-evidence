import { SocialLogin } from '@capgo/capacitor-social-login';

export async function googleLoginNative() {
  return SocialLogin.signIn({ provider: 'google' });
}

export async function googleLogoutNative() {
  return SocialLogin.signOut({ provider: 'google' });
}
