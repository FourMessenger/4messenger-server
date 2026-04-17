@echo off
REM Build script for 4 Messenger Bot Docker image (Windows)

echo Building 4 Messenger Bot Docker image...
echo.

REM Check if Docker is installed
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Docker is not installed or not in PATH
    echo Please install Docker Desktop from https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

REM Check if Docker daemon is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Docker daemon is not running
    echo Please start Docker Desktop and wait for it to fully load
    pause
    exit /b 1
)

REM Build the image
echo Building image '4messenger-bot'...
docker build -t 4messenger-bot .

if %errorlevel% equ 0 (
    echo.
    echo SUCCESS: Docker image '4messenger-bot' built successfully!
    echo.
    echo To enable Docker bots, set "enabled": true in config.json under bots.docker
) else (
    echo.
    echo ERROR: Failed to build Docker image
    pause
    exit /b 1
)

pause
