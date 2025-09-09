let gisInitDone = false;

export function initGIS(webClientId) {
  if (gisInitDone || !window.google?.accounts?.id) return;
  window.google.accounts.id.initialize({
    client_id: webClientId,
    callback: (resp) => {
      // One Tap callback - handle if needed
      console.debug('GIS OneTap callback', resp);
    }
  });
  gisInitDone = true;
}

// Placeholder interactive login - implement with your button / flow
export function googleLoginWebInteractive() {
  return new Promise((resolve, reject) => {
    // In real app, show GIS button or one tap, then call resolve({ credential: <jwt> })
    reject(new Error('Implement GIS button/popup flow for your web app'));
  });
}

export async function googleLogoutWeb() {
  // Web logout typically means clearing your session or tokens server-side
  return;
}
