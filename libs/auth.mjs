import express from 'express';
const router = express.Router();
import crypto from 'crypto';
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { Users, Credentials } from './db.mjs';

router.use(express.json());

function csrfCheck(req, res, next) {
  if (req.header('X-Requested-With') != 'XMLHttpRequest') {
    return res.status(400).json({ error: 'invalid access.' });
  }
  next();
};

async function sessionCheck(req, res, next) {
  if (!req.session['signed-in'] || !req.session.username) {
    return res.status(401).json({ error: 'not signed in.' });
  }
  const user = await Users.findByUsername(req.session.username);
  if (!user) {
    return res.status(401).json({ error: 'user not found.' });
  }
  res.locals.user = user;
  next();
};

function getOrigin(userAgent) {
  let origin = process.env.ORIGIN;
  const appRe = /^[a-zA-z0-9_.]+/;
  const match = userAgent.match(appRe);
  if (match) {
    if (process.env.ANDROID_PACKAGENAME && process.env.ANDROID_SHA256HASH) {
      const package_names = process.env.ANDROID_PACKAGENAME.split(",").map(name => name.trim());
      const hashes = process.env.ANDROID_SHA256HASH.split(",").map(hash => hash.trim());
      const appName = match;
      for (let i = 0; i < package_names.length; i++) {
        if (appName === package_names[i]) {
          const octArray = hashes[i].split(':').map((h) => parseInt(h, 16), );
          const androidHash = isoBase64URL.fromBuffer(octArray);
          origin = `android:apk-key-hash:${androidHash}`;
          break;
        }
      }
    }
  }
  return origin;
}

router.post('/username', async (req, res) => {
  const { username } = req.body;
  try {
    if (username && /^[a-zA-Z0-9@\.\-_]+$/.test(username)) {
      let user = await Users.findByUsername(username);
      if (!user) {
        user = {
          id: isoBase64URL.fromBuffer(crypto.randomBytes(32)),
          username,
          displayName: username,
        };
        await Users.update(user);
      }
      req.session.username = username;
      return res.json(user);
    } else {
      throw new Error('Invalid username');
    }
  } catch (e) {
    console.error(e);
    return res.status(400).send({ error: e.message });
  }
});

router.post('/password', async (req, res) => {
  if (!req.body.password) {
    return res.status(401).json({ error: 'Enter at least one random letter.' });
  }
  const user = await Users.findByUsername(req.session.username);
  if (!user) {
    return res.status(401).json({ error: 'Enter username first.' });
  }
  req.session['signed-in'] = 'yes';
  return res.json(user);
});

router.post('/userinfo', csrfCheck, sessionCheck, (req, res) => {
  const { user } = res.locals;
  return res.json(user);
});

router.post('/updateDisplayName', csrfCheck, sessionCheck, async (req, res) => {
  const { newName } = req.body;
  if (newName) {
    const { user } = res.locals;
    user.displayName = newName;
    await Users.update(user);
    return res.json(user);
  } else {
    return res.status(400);
  }
});

router.get('/signout', (req, res) => {
  req.session.destroy()
  return res.redirect(307, '/');
});

router.post('/getKeys', csrfCheck, sessionCheck, async (req, res) => {
  const { user } = res.locals;
  const credentials = await Credentials.findByUserId(user.id);
  return res.json(credentials || []);
});

router.post('/renameKey', csrfCheck, sessionCheck, async (req, res) => {
  const { credId, newName } = req.body;
  const { user } = res.locals;
  const credential = await Credentials.findById(credId);
  if (!user || user.id !== credential?.user_id) {
    return res.status(401).json({ error: 'User not authorized.' });
  }
  credential.name = newName;
  await Credentials.update(credential);
  return res.json(credential);
});

router.post('/removeKey', csrfCheck, sessionCheck, async (req, res) => {
  const credId = req.query.credId;
  const { user } = res.locals;
  await Credentials.remove(credId, user.id);
  return res.json({});
});

router.post('/registerRequest', csrfCheck, sessionCheck, async (req, res) => {
  const { user } = res.locals;
  try {
    const excludeCredentials = [];
    const credentials = await Credentials.findByUserId(user.id);
    for (const cred of credentials) {
      excludeCredentials.push({
        id: isoBase64URL.toBuffer(cred.id),
        type: 'public-key',
        transports: cred.transports,
      });
    }
    const authenticatorSelection = {
      authenticatorAttachment: 'platform',
      requireResidentKey: true
    }
    const attestationType = 'none';
    const options = await generateRegistrationOptions({
      rpName: process.env.RP_NAME,
      rpID: process.env.HOSTNAME,
      userID: user.id,
      userName: user.username,
      userDisplayName: user.displayName || user.username,
      attestationType,
      excludeCredentials,
      authenticatorSelection,
    });
    req.session.challenge = options.challenge;
    return res.json(options);
  } catch (e) {
    console.error(e);
    return res.status(400).send({ error: e.message });
  }
});

router.post('/registerResponse', csrfCheck, sessionCheck, async (req, res) => {
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get('User-Agent'));
  const expectedRPID = process.env.HOSTNAME;
  const credential = req.body;
  try {
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      requireUserVerification: false,
    });
    const { verified, registrationInfo } = verification;
    if (!verified) {
      throw new Error('User verification failed.');
    }
    const { credentialPublicKey, credentialID } = registrationInfo;
    const base64PublicKey = isoBase64URL.fromBuffer(credentialPublicKey);
    const base64CredentialID = isoBase64URL.fromBuffer(credentialID);
    const { user } = res.locals;
    await Credentials.update({
      id: base64CredentialID,
      publicKey: base64PublicKey,
      name: req.useragent.platform,
      transports: credential.response.transports || [],
      registered: (new Date()).getTime(),
      last_used: null,
      user_id: user.id,
    });
    delete req.session.challenge;
    return res.json(user);
  } catch (e) {
    delete req.session.challenge;
    console.error(e);
    return res.status(400).send({ error: e.message });
  }
});

router.post('/signinRequest', csrfCheck, async (req, res) => {
  try {
    const options = await generateAuthenticationOptions({
      rpID: process.env.HOSTNAME,
      allowCredentials: [],
    });
    req.session.challenge = options.challenge;
    return res.json(options)
  } catch (e) {
    console.error(e);
    return res.status(400).json({ error: e.message });
  }
});

router.post('/signinResponse', csrfCheck, async (req, res) => {
  const credential = req.body;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get('User-Agent'));
  const expectedRPID = process.env.HOSTNAME;
  try {
    const cred = await Credentials.findById(credential.id);
    if (!cred) {
      throw new Error('Matching credential not found on the server. Try signing in with a password.');
    }
    const user = await Users.findById(cred.user_id);
    if (!user) {
      throw new Error('User not found.');
    }
    const authenticator = {
      credentialPublicKey: isoBase64URL.toBuffer(cred.publicKey),
      credentialID: isoBase64URL.toBuffer(cred.id),
      transports: cred.transports,
    };
    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      authenticator,
      requireUserVerification: false,
    });
    const { verified, authenticationInfo } = verification;
    if (!verified) {
      throw new Error('User verification failed.');
    }
    cred.last_used = (new Date()).getTime();
    await Credentials.update(cred);
    delete req.session.challenge;
    req.session.username = user.username;
    req.session['signed-in'] = 'yes';
    return res.json(user);
  } catch (e) {
    delete req.session.challenge;
    console.error(e);
    return res.status(400).json({ error: e.message });
  }
});

export { router as auth };