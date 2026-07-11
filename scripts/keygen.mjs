import crypto from 'node:crypto';
import fs from 'node:fs/promises';
const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
const out={publicKey:publicKey.export({type:'spki',format:'pem'}),privateKey:privateKey.export({type:'pkcs8',format:'pem'})};
await fs.mkdir('./secrets',{recursive:true});await fs.writeFile('./secrets/deployer.json',JSON.stringify(out,null,2),{mode:0o600});
console.log('Created secrets/deployer.json (do not commit it)');
