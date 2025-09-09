import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.housetech.app',
  appName: 'HOUSETECH',
  webDir: 'web', // ker je tvoj frontend v /web (ne v dist/build)
  server: {
    androidScheme: 'https'
  },
  plugins: {
    SocialLogin: {
      google: {
        // uporabi Web Client ID za VSE platforme
        webClientId: 'YOUR_WEB_CLIENT_ID.apps.googleusercontent.com',
        // opcijsko; lahko pustiš prazno, če uporabljaš izključno Web Client ID
        iOSClientId: 'YOUR_IOS_CLIENT_ID.apps.googleusercontent.com',
        mode: 'offline' // če žeš refresh token
      }
    }
  }
};

export default config;
