import firebaseJson from '../firebase.json' assert { type: 'json' };
import { getFirestore } from 'firebase-admin/firestore';
import { initializeApp } from 'firebase-admin/app';

if (process.env.NODE_ENV === 'localhost') {
  process.env.DOMAIN = 'http://localhost:8080';
  process.env.GOOGLE_CLOUD_PROJECT = 'passkeys-demo';
  process.env.FIRESTORE_EMULATOR_HOST = `${firebaseJson.emulators.firestore.host}:${firebaseJson.emulators.firestore.port}`;
} else if (process.env.NODE_ENV === 'development') {
  process.env.DOMAIN = 'https://passkeys-demo.appspot.com';
}

initializeApp();
const store = getFirestore();
store.settings({ ignoreUndefinedProperties: true });

export const Users = {
  findById: async (user_id) => {
    const doc = await store.collection('users').doc(user_id).get();
    if (doc) {
      const credential = doc.data();
      return credential;
    } else {
      return;
    }
  },

  findByUsername: async (username) => {
    const results = [];
    const refs = await store.collection('users')
      .where('username', '==', username).get();
    if (refs) {
      refs.forEach(user => results.push(user.data()));
    }
    return results.length > 0 ? results : undefined;
  },

  update: async (user) => {
    const ref = store.collection('users').doc(user.id);
      return ref.set(user);
  }
}

export const Credentials = {
  findById: async (credential_id) => {
    const doc = await store.collection('credentials').doc(credential_id).get();
    if (doc) {
      const credential = doc.data();
      return credential;
    } else {
      return;
    }
  },

  findByUserId: async (user_id) => {
    const results = [];
    const refs = await store.collection('credentials')
      .where('user_id', '==', user_id)
      .orderBy('registered', 'desc').get();
    refs.forEach(cred => results.push(cred.data()));
    return results;
  },

  update: async (credential) => {
    const ref = store.collection('credentials').doc(credential.id);
    return ref.set(credential);
  },
  
  remove: async (credential_id, user_id) => {
    const ref = store.collection('credentials').doc(credential_id);
    return ref.delete();
  }
}