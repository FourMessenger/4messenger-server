#!/usr/bin/env node
/**
 * Cross-platform Docker build script for 4 Messenger Bots
 * Works on Windows, macOS, and Linux
 */

const { execSync, spawn } = require('child_process');
const os = require('os');
const path = require('path');

const IMAGE_NAME = '4messenger-bot';
const SCRIPT_DIR = __dirname;

console.log('╔════════════════════════════════════════════════╗');
console.log('║     4 Messenger Bot Docker Image Builder       ║');
console.log('╚════════════════════════════════════════════════╝');
console.log('');
console.log(`Platform: ${os.platform()} (${os.arch()})`);
console.log(`Working directory: ${SCRIPT_DIR}`);
console.log('');

// Check if Docker is installed
function checkDockerInstalled() {
  try {
    execSync('docker --version', { stdio: 'pipe' });
    return true;
  } catch (e) {
    return false;
  }
}

// Check if Docker daemon is running
function checkDockerRunning() {
  try {
    execSync('docker info', { stdio: 'pipe', timeout: 10000 });
    return true;
  } catch (e) {
    return false;
  }
}

// Build the Docker image
function buildImage() {
  return new Promise((resolve, reject) => {
    console.log(`Building Docker image '${IMAGE_NAME}'...`);
    console.log('');
    
    const docker = spawn('docker', ['build', '-t', IMAGE_NAME, '.'], {
      cwd: SCRIPT_DIR,
      stdio: 'inherit',
      shell: true
    });
    
    docker.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`Docker build failed with code ${code}`));
      }
    });
    
    docker.on('error', (err) => {
      reject(err);
    });
  });
}

// Main function
async function main() {
  // Check Docker installation
  console.log('Checking Docker installation...');
  if (!checkDockerInstalled()) {
    console.error('');
    console.error('❌ ERROR: Docker is not installed or not in PATH');
    console.error('');
    console.error('Please install Docker:');
    if (os.platform() === 'win32') {
      console.error('  Windows: https://www.docker.com/products/docker-desktop');
    } else if (os.platform() === 'darwin') {
      console.error('  macOS: https://www.docker.com/products/docker-desktop');
      console.error('  Or: brew install --cask docker');
    } else {
      console.error('  Linux: https://docs.docker.com/engine/install/');
      console.error('  Or: sudo apt-get install docker.io');
    }
    process.exit(1);
  }
  console.log('✓ Docker is installed');
  
  // Check Docker daemon
  console.log('Checking Docker daemon...');
  if (!checkDockerRunning()) {
    console.error('');
    console.error('❌ ERROR: Docker daemon is not running');
    console.error('');
    if (os.platform() === 'win32') {
      console.error('Please start Docker Desktop and wait for it to fully load.');
      console.error('Look for the Docker whale icon in your system tray.');
    } else if (os.platform() === 'darwin') {
      console.error('Please start Docker Desktop from your Applications folder.');
    } else {
      console.error('Please start the Docker daemon:');
      console.error('  sudo systemctl start docker');
    }
    process.exit(1);
  }
  console.log('✓ Docker daemon is running');
  console.log('');
  
  // Build the image
  try {
    await buildImage();
    console.log('');
    console.log('╔════════════════════════════════════════════════╗');
    console.log('║  ✓ SUCCESS: Docker image built successfully!   ║');
    console.log('╚════════════════════════════════════════════════╝');
    console.log('');
    console.log('Next steps:');
    console.log('1. Open server/config.json');
    console.log('2. Set "bots.docker.enabled" to true');
    console.log('3. Restart the server');
    console.log('');
  } catch (err) {
    console.error('');
    console.error('❌ ERROR: Failed to build Docker image');
    console.error(err.message);
    process.exit(1);
  }
}

main();
