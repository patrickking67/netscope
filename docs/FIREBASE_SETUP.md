# Firebase Setup Guide

This guide walks through setting up Firebase for your own fork of NetScope. Firebase provides Google Sign-In authentication and Firestore for cloud-saved results.

## 1. Create a Firebase Project

1. Go to the [Firebase Console](https://console.firebase.google.com/)
2. Click **Add project**
3. Enter a project name (e.g. `netscope`)
4. Disable Google Analytics (optional, not used by NetScope)
5. Click **Create project**

## 2. Register a Web App

1. From the project dashboard, click the **Web** icon (`</>`)
2. Enter an app nickname (e.g. `NetScope Web`)
3. Skip Firebase Hosting setup
4. Click **Register app**
5. Copy the `firebaseConfig` object — you'll need it in step 5

## 3. Enable Google Authentication

1. In the Firebase Console, go to **Build > Authentication**
2. Click **Get started**
3. Under **Sign-in method**, click **Google**
4. Toggle **Enable**
5. Select a support email address
6. Click **Save**

### Add Authorized Domains

Under **Authentication > Settings > Authorized domains**, add your GitHub Pages domain:

```
yourusername.github.io
```

## 4. Create Firestore Database

1. Go to **Build > Firestore Database**
2. Click **Create database**
3. Choose a location closest to your users
4. Start in **production mode**

### Security Rules

Replace the default rules with:

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId}/results/{resultId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

This ensures users can only read and write their own saved results.

## 5. Update Firebase Config

Edit `js/firebase-config.js` and replace the config object with your own:

```js
const firebaseConfig = {
  apiKey: "YOUR_API_KEY",
  authDomain: "YOUR_PROJECT.firebaseapp.com",
  projectId: "YOUR_PROJECT",
  storageBucket: "YOUR_PROJECT.firebasestorage.app",
  messagingSenderId: "YOUR_SENDER_ID",
  appId: "YOUR_APP_ID"
};
```

These are client-side keys and are safe to commit to a public repository.

## 6. Deploy and Test

1. Push your changes to the `main` branch
2. Wait for GitHub Actions to deploy
3. Visit your site and click **Sign In**
4. Run some tests, then use **Save to Cloud** in the export panel
5. Verify saved results appear under **My Results**

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Sign-in popup blocked | Allow popups for your GitHub Pages domain |
| Auth domain not authorized | Add your domain under Authentication > Settings > Authorized domains |
| Firestore permission denied | Check that security rules match the ones above |
| Config values wrong | Re-copy from Firebase Console > Project Settings > Your apps |
