#!/usr/bin/env node
/**
 * Generate VAPID keys for Web Push Notifications
 * 
 * VAPID keys are required to send push notifications through browsers.
 * This script generates a public/private key pair and updates your config.json.
 * 
 * Usage: node generate-vapid-keys.js
 */

const path = require('path');
const fs = require('fs');

// Try to load web-push
let webpush;
try {
  webpush = require('web-push');
} catch (err) {
  console.error('ERROR: web-push is not installed!');
  console.error('Please run: npm install web-push');
  process.exit(1);
}

console.log('🔑 Generating VAPID Keys for Web Push Notifications...\n');

// Generate the keys
const vapidKeys = webpush.generateVAPIDKeys();

console.log('✅ VAPID Keys generated successfully!\n');
console.log('📋 Public Key (share with clients):');
console.log('   ' + vapidKeys.publicKey);
console.log('\n🔒 Private Key (KEEP SECRET, never share):');
console.log('   ' + vapidKeys.privateKey);
console.log('\n');

// Load existing config
const configPath = path.join(__dirname, 'config.json');
let config;

try {
  config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
} catch (err) {
  console.error(`ERROR: Could not read ${configPath}:`, err.message);
  process.exit(1);
}

// Update config with new keys
if (!config.push) {
  config.push = {};
}

config.push.enabled = true;
config.push.vapidPublicKey = vapidKeys.publicKey;
config.push.vapidPrivateKey = vapidKeys.privateKey;
config.push.vapidSubject = config.push.vapidSubject || 'mailto:admin@4messenger.com';

// Save updated config
try {
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  console.log('✨ Configuration updated successfully!\n');
  console.log('📁 Updated config.json with new VAPID keys');
  console.log('✅ Push notifications are now ready to use!');
  console.log('\n⚠️  IMPORTANT: Keep your private key secret and never commit it to version control!\n');
} catch (err) {
  console.error(`ERROR: Could not write to ${configPath}:`, err.message);
  process.exit(1);
}
