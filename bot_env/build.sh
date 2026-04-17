#!/bin/bash
# Build script for 4 Messenger Bot Docker image (Linux/macOS)
# For Windows, use build.bat or build.js

set -e

echo "╔════════════════════════════════════════════════╗"
echo "║     4 Messenger Bot Docker Image Builder       ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
echo "Platform: $(uname -s) ($(uname -m))"
echo "Working directory: $(pwd)"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ ERROR: Docker is not installed or not in PATH"
    echo ""
    echo "Please install Docker:"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "  macOS: https://www.docker.com/products/docker-desktop"
        echo "  Or: brew install --cask docker"
    else
        echo "  Linux: https://docs.docker.com/engine/install/"
        echo "  Or: sudo apt-get install docker.io"
    fi
    exit 1
fi
echo "✓ Docker is installed"

# Check if Docker daemon is running
if ! docker info &> /dev/null; then
    echo "❌ ERROR: Docker daemon is not running"
    echo ""
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "Please start Docker Desktop from your Applications folder."
    else
        echo "Please start the Docker daemon:"
        echo "  sudo systemctl start docker"
    fi
    exit 1
fi
echo "✓ Docker daemon is running"
echo ""

echo "Building Docker image '4messenger-bot'..."
docker build -t 4messenger-bot .

if [ $? -eq 0 ]; then
    echo ""
    echo "╔════════════════════════════════════════════════╗"
    echo "║  ✓ SUCCESS: Docker image built successfully!   ║"
    echo "╚════════════════════════════════════════════════╝"
    echo ""
    echo "Next steps:"
    echo "1. Open server/config.json"
    echo "2. Set \"bots.docker.enabled\" to true"
    echo "3. Restart the server"
    echo ""
else
    echo ""
    echo "❌ ERROR: Docker image build failed!"
    exit 1
fi
