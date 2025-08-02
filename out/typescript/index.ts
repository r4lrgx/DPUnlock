// Basic DPAPI usage in TS: encrypt with @primno/dpapi, decrypt via external DPUnlock.exe.
// No extra decryption libs needed in Node.js.
// Uses "CurrentUser" scope and no entropy.

import { execFileSync } from 'child_process';
import { Dpapi } from '@primno/dpapi';
import path from 'path';

const buffer = Buffer.from('Hello world', 'utf-8');

try {
 const encrypted = Dpapi.protectData(buffer, null, 'CurrentUser');

 const decryptedBase64 = execFileSync(path.resolve('../DPUnlock.exe'), ['--input', Buffer.from(encrypted).toString('base64'), '--entropy', '', '--scope', 'CurrentUser'], { encoding: 'utf8' }).trim();

 const decryptedBuffer = Buffer.from(decryptedBase64, 'base64');

 console.log('Decrypted:', decryptedBuffer.toString('utf-8'));
} catch (err) {
 console.error('Decryption failed:', err.message);
 process.exit(1);
}
