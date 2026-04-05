#!/bin/bash
# Android Security Testing Environment Setup Script

set -e

echo "🔧 Android Security Testing Environment Setup"
echo "=============================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "${RED}This script is designed for macOS${NC}"
    exit 1
fi

# 1. Check Homebrew
echo "📦 Checking Homebrew..."
if ! command -v brew &> /dev/null; then
    echo "${YELLOW}Installing Homebrew...${NC}"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
else
    echo "${GREEN}✓ Homebrew installed${NC}"
fi

# 2. Check Android Command Line Tools
echo ""
echo "📱 Checking Android SDK..."
ANDROID_SDK="$HOME/Library/Android/sdk"

if [ ! -d "$ANDROID_SDK" ]; then
    echo "${YELLOW}Installing Android Command Line Tools...${NC}"
    brew install --cask android-commandlinetools
else
    echo "${GREEN}✓ Android SDK found at $ANDROID_SDK${NC}"
fi

# 3. Check jadx
echo ""
echo "🔍 Checking jadx (Java decompiler)..."
if ! command -v jadx &> /dev/null; then
    echo "${YELLOW}Installing jadx...${NC}"
    brew install jadx
else
    echo "${GREEN}✓ jadx installed${NC}"
fi

# 4. Check adb
echo ""
echo "🔌 Checking adb..."
if [ ! -f "$ANDROID_SDK/platform-tools/adb" ]; then
    echo "${YELLOW}Installing platform-tools...${NC}"
    $ANDROID_SDK/cmdline-tools/latest/bin/sdkmanager "platform-tools"
else
    echo "${GREEN}✓ adb available${NC}"
fi

# 5. Setup system images for emulator
echo ""
echo "📥 Checking ARM64 system image (API 35)..."
if [ ! -d "$ANDROID_SDK/system-images/android-35/google_apis/arm64-v8a" ]; then
    echo "${YELLOW}Downloading ARM64 system image (this may take a while)...${NC}"
    $ANDROID_SDK/cmdline-tools/latest/bin/sdkmanager "system-images;android-35;google_apis;arm64-v8a"
else
    echo "${GREEN}✓ ARM64 system image ready${NC}"
fi

# 6. Check/Create AVD
echo ""
echo "🎮 Checking Android Virtual Device..."
AVD_NAME="security_test_api35"

if ! $ANDROID_SDK/cmdline-tools/latest/bin/avdmanager list avd | grep -q "$AVD_NAME"; then
    echo "${YELLOW}Creating AVD: $AVD_NAME...${NC}"
    echo "no" | $ANDROID_SDK/cmdline-tools/latest/bin/avdmanager create avd \
        -n "$AVD_NAME" \
        -k "system-images;android-35;google_apis;arm64-v8a" \
        -d "pixel_8_pro"
    echo "${GREEN}✓ AVD created${NC}"
else
    echo "${GREEN}✓ AVD exists${NC}"
fi

# 7. Optional: Install useful tools
echo ""
echo "🛠️  Optional tools..."

if ! command -v apktool &> /dev/null; then
    echo "${YELLOW}Installing apktool...${NC}"
    brew install apktool
fi

if ! command -v python3 &> /dev/null; then
    echo "${YELLOW}Python3 not found, please install Python3${NC}"
else
    echo "${GREEN}✓ Python3 available${NC}"
fi

# 8. Setup complete
echo ""
echo "${GREEN}=============================================="
echo "✅ Setup Complete!"
echo "==============================================${NC}"
echo ""
echo "Quick Start Commands:"
echo "  • Start emulator: $ANDROID_SDK/emulator/emulator -avd $AVD_NAME"
echo "  • List devices: adb devices"
echo "  • Decompile APK: jadx -d output_dir app.apk"
echo ""
echo "Environment Variables (add to ~/.zshrc or ~/.bash_profile):"
echo "  export ANDROID_HOME=$ANDROID_SDK"
echo "  export PATH=\$PATH:\$ANDROID_HOME/emulator"
echo "  export PATH=\$PATH:\$ANDROID_HOME/platform-tools"
echo ""
