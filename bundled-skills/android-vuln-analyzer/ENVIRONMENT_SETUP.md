# Android Vulnerability Verification - Environment Setup

**Last Updated**: 2026-02-28
**Purpose**: Complete setup guide for dynamic verification tools (Step 7)

---

## Overview

This guide documents all tools, installation steps, and common pitfalls encountered during Android vulnerability verification. Use this to set up a complete testing environment for Step 7 dynamic verification.

---

## Required Tools

### 1. Android SDK & Emulator

**Installation**:
```bash
# Install Android Studio or command-line tools
# Download from: https://developer.android.com/studio

# Verify installation
adb version
emulator -version
```

**Recommended Emulator Configuration**:
- API Level: 35 (Android 15) or latest
- Architecture: arm64-v8a (for better app compatibility)
- Device: Pixel 8 Pro or similar
- Storage: 8GB+ recommended

**Creating Emulator**:
```bash
# List available system images
sdkmanager --list | grep system-images

# Install system image (example)
sdkmanager "system-images;android-35;google_apis;arm64-v8a"

# Create AVD
avdmanager create avd -n Pixel_8_Pro_API35_arm \
  -k "system-images;android-35;google_apis;arm64-v8a" \
  -d "pixel_8_pro"

# Launch emulator
emulator -avd Pixel_8_Pro_API35_arm &
```

---

### 2. mitmproxy (MITM Attack Testing)

**Purpose**: Test certificate pinning, intercept HTTPS traffic, modify requests/responses

**Installation** (macOS):
```bash
brew install mitmproxy
```

**Installation** (Linux):
```bash
sudo apt install mitmproxy
# or
pip3 install mitmproxy
```

**Verification**:
```bash
$ mitmproxy --version
Mitmproxy: 12.2.1
Python:    3.x.x
```

**Basic Usage**:
```bash
# Start mitmproxy with script
mitmproxy -s intercept_script.py

# Configure emulator proxy (in another terminal)
adb shell settings put global http_proxy 10.0.2.2:8080

# Install mitmproxy certificate on emulator
adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/
# Then: Settings > Security > Install from storage
```

**Common Pitfalls**:
- ⚠️ Certificate must be installed as "system" cert for API 24+
- ⚠️ Some apps ignore global proxy settings (need VPN mode)
- ⚠️ Certificate pinning will cause connection failures (this is expected!)

---

### 3. Frida (Runtime Instrumentation)

**Purpose**: Hook Java/Native methods, inspect runtime behavior, modify execution

**Installation**:

```bash
# Install frida and frida-tools
pip3 install --break-system-packages frida frida-tools
```

**⚠️ CRITICAL PITFALL #1**: `externally-managed-environment` error

```bash
# ❌ This will fail on some systems:
pip3 install frida frida-tools

# Error: externally-managed-environment
# This Python installation is managed by system package manager

# ✅ Solution: Use --break-system-packages flag
pip3 install --break-system-packages frida frida-tools

# Alternative: Use virtual environment
python3 -m venv ~/frida-env
source ~/frida-env/bin/activate
pip install frida frida-tools
```

**Verification**:
```bash
$ frida --version
17.7.3

$ frida-ps --help
# Should show help output
```

---

### 4. frida-server (Device-Side Component)

**Purpose**: Required on Android device/emulator for Frida to work

**Installation**:

```bash
# 1. Download frida-server (match version with frida client!)
FRIDA_VERSION=$(frida --version)
curl -L -o frida-server.xz \
  "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-arm64.xz"

# 2. Extract
unxz frida-server.xz

# 3. Push to device
adb push frida-server /data/local/tmp/frida-server

# 4. Make executable
adb shell chmod 755 /data/local/tmp/frida-server

# 5. Run frida-server (keep terminal open)
adb shell /data/local/tmp/frida-server &
```

**⚠️ CRITICAL PITFALL #2**: Version mismatch

```bash
# ❌ Frida client 17.7.3 + frida-server 17.7.2 = Connection failures

# ✅ Always match versions exactly:
$ frida --version
17.7.3
# Download: frida-server-17.7.3-android-arm64.xz
```

**⚠️ CRITICAL PITFALL #3**: Architecture mismatch

```bash
# Check emulator architecture first
$ adb shell getprop ro.product.cpu.abi
arm64-v8a

# Download correct architecture:
# - arm64-v8a → frida-server-*-android-arm64.xz
# - armeabi-v7a → frida-server-*-android-arm.xz
# - x86_64 → frida-server-*-android-x86_64.xz
```

**Verification**:
```bash
# Check if frida-server is running
$ adb shell ps -A | grep frida
shell         5432   366 10234020  29156 poll_schedule_timeout 0 S frida-server

# Test connection from host
$ frida-ps -D emulator-5554
PID  Name
---  ----
1234 com.example.app
...
```

---

### 5. tcpdump (Network Capture)

**Purpose**: Capture network traffic, analyze protocols, detect HTTP vs HTTPS

**Installation**: Usually pre-installed on Android emulators

**Verification**:
```bash
$ adb shell which tcpdump
/system/xbin/tcpdump
```

**Usage**:
```bash
# Capture to file on device
adb shell "tcpdump -w /sdcard/capture.pcap" &
TCPDUMP_PID=$!

# ... trigger app activity ...

# Stop capture (after ~10 seconds)
adb shell "kill $TCPDUMP_PID"

# Pull capture file
adb pull /sdcard/capture.pcap

# Analyze with tcpdump or Wireshark
tcpdump -r capture.pcap -n | head -50
```

**⚠️ CRITICAL PITFALL #4**: Background process management

```bash
# ❌ This doesn't work well:
adb shell tcpdump -w /sdcard/capture.pcap &

# Shell exits immediately, tcpdump stops

# ✅ Better approach:
adb shell "nohup tcpdump -w /sdcard/capture.pcap > /dev/null 2>&1 &"
# Or use screen/tmux on device if available
```

**⚠️ CRITICAL PITFALL #5**: frida-server SELinux permission error

```bash
# ❌ Error when starting frida-server:
# "Unable to load SELinux policy from the kernel: Permission denied"
# Exit code: 144

# Common on non-rooted emulators with enforcing SELinux

# ✅ Solutions:
# 1. Use rooted emulator/device:
adb root
adb shell setenforce 0  # Temporarily disable SELinux

# 2. Or use system emulator with root access:
emulator -avd <name> -writable-system

# 3. Or accept the limitation:
# - frida-server may still work for spawn mode
# - Some hooking features may be limited
# - Try spawning apps instead of attaching

# Verify SELinux status:
$ adb shell getenforce
Enforcing  # or Permissive
```

---

## Common Pitfalls Summary

### Installation Issues

| Problem | Symptom | Solution |
|---------|---------|----------|
| pip externally-managed | `error: externally-managed-environment` | Add `--break-system-packages` flag |
| Version mismatch | Frida connection fails | Match frida and frida-server versions exactly |
| Architecture mismatch | frida-server won't start | Check `adb shell getprop ro.product.cpu.abi` |
| Missing permissions | frida-server: permission denied | `adb shell chmod 755 /data/local/tmp/frida-server` |

### Runtime Issues

| Problem | Symptom | Solution |
|---------|---------|----------|
| Frida attach fails | `unable to access process with pid` | Use spawn mode or check selinux |
| frida-server SELinux error | `Unable to load SELinux policy` (exit 144) | Use rooted emulator or `setenforce 0` |
| adb root fails | `adbd cannot run as root in production builds` | Use rooted emulator or custom ROM |
| run-as fails | `package not debuggable` | Use debuggable build or root access |
| mitmproxy cert rejected | Connection fails even with cert installed | App has certificate pinning (expected) |

### Frida-Specific Issues

| Problem | Symptom | Solution |
|---------|---------|----------|
| `--no-pause` not recognized | `unrecognized arguments: --no-pause` | Remove flag (not in all versions) |
| Spawn vs Attach | Different behavior | Use `-f com.package` for spawn, `-n "Name"` for attach |
| Process name wrong | `Failed to spawn: unable to find process` | Use package name, not app display name |

---

## Complete Setup Script

Save this as `setup_environment.sh`:

```bash
#!/bin/bash
set -e

echo "=== Android Vulnerability Verification Environment Setup ==="

# 1. Check prerequisites
echo "[1/6] Checking prerequisites..."
command -v adb >/dev/null 2>&1 || { echo "Error: adb not found. Install Android SDK."; exit 1; }
command -v brew >/dev/null 2>&1 || { echo "Warning: brew not found. Install manually."; }

# 2. Install mitmproxy
echo "[2/6] Installing mitmproxy..."
if command -v brew >/dev/null 2>&1; then
    brew install mitmproxy || echo "mitmproxy already installed"
else
    pip3 install --break-system-packages mitmproxy || echo "Install mitmproxy manually"
fi

# 3. Install frida and frida-tools
echo "[3/6] Installing frida..."
pip3 install --break-system-packages frida frida-tools || {
    echo "Trying without --break-system-packages..."
    pip3 install frida frida-tools
}

# 4. Get frida version
FRIDA_VERSION=$(frida --version)
echo "Frida version: $FRIDA_VERSION"

# 5. Check emulator architecture
echo "[4/6] Checking emulator architecture..."
adb wait-for-device
ARCH=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
echo "Emulator architecture: $ARCH"

# Map architecture to frida-server variant
case $ARCH in
    arm64-v8a)
        FRIDA_ARCH="arm64"
        ;;
    armeabi-v7a)
        FRIDA_ARCH="arm"
        ;;
    x86_64)
        FRIDA_ARCH="x86_64"
        ;;
    x86)
        FRIDA_ARCH="x86"
        ;;
    *)
        echo "Unknown architecture: $ARCH"
        exit 1
        ;;
esac

# 6. Download frida-server
echo "[5/6] Downloading frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}..."
FRIDA_SERVER_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}.xz"

curl -L -o frida-server.xz "$FRIDA_SERVER_URL"
unxz -f frida-server.xz
chmod +x frida-server

# 7. Deploy to emulator
echo "[6/6] Deploying frida-server to emulator..."
adb push frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# Start frida-server
echo "Starting frida-server..."
adb shell "/data/local/tmp/frida-server &"
sleep 2

# Verify
echo ""
echo "=== Verification ==="
echo "mitmproxy version:"
mitmproxy --version | head -1

echo ""
echo "frida version:"
frida --version

echo ""
echo "frida-server status:"
adb shell ps -A | grep frida-server || echo "frida-server not running!"

echo ""
echo "frida connection test:"
frida-ps -D $(adb devices | grep -v "List" | awk '{print $1}' | head -1) | head -5

echo ""
echo "=== Setup Complete ==="
echo "Tools installed:"
echo "  ✅ mitmproxy"
echo "  ✅ frida + frida-tools"
echo "  ✅ frida-server (on emulator)"
echo ""
echo "Next steps:"
echo "  1. Run MITM test: mitmproxy -s intercept_script.py"
echo "  2. Run Frida hook: frida -D <device> -f <package> -l hook.js"
echo "  3. Capture traffic: adb shell tcpdump -w /sdcard/capture.pcap"
```

**Usage**:
```bash
chmod +x setup_environment.sh
./setup_environment.sh
```

---

## Testing Workflow

### 1. Environment Check
```bash
# Verify all tools
mitmproxy --version
frida --version
adb devices
adb shell ps -A | grep frida-server
```

### 2. Network Capture Test
```bash
# Start capture
adb shell "tcpdump -w /sdcard/test_capture.pcap" &

# Trigger app activity (launch app, navigate, etc.)
adb shell am start com.example.app/.MainActivity
sleep 10

# Stop and analyze
adb shell pkill tcpdump
adb pull /sdcard/test_capture.pcap
tcpdump -r test_capture.pcap -n | grep -E "http|https|443|80"
```

### 3. Frida Hook Test
```bash
# Create simple test script
cat > test_hook.js << 'EOF'
Java.perform(function() {
    console.log("[*] Frida connected!");

    // Hook a common class to verify it works
    var Log = Java.use("android.util.Log");
    Log.d.overload("java.lang.String", "java.lang.String").implementation = function(tag, msg) {
        console.log("[LOG] " + tag + ": " + msg);
        return this.d(tag, msg);
    };
});
EOF

# Run hook
frida -D emulator-5554 -f com.example.app -l test_hook.js
```

### 4. MITM Test
```bash
# Start mitmproxy
mitmproxy &
MITM_PID=$!

# Configure proxy
adb shell settings put global http_proxy 10.0.2.2:8080

# Launch app and observe traffic
adb shell am start com.example.app/.MainActivity

# Reset proxy when done
adb shell settings put global http_proxy :0
kill $MITM_PID
```

---

## Troubleshooting

### Frida Issues

**Problem**: "Failed to attach: unable to access process"

**Solutions**:
1. Try spawn mode instead of attach:
   ```bash
   # Instead of: frida -D device -n "AppName"
   frida -D device -f com.package.name -l script.js
   ```

2. Check SELinux status:
   ```bash
   adb shell getenforce
   # If "Enforcing", try:
   adb shell setenforce 0  # May not work on production builds
   ```

3. Use debuggable build if possible

4. Try attaching to different process (some apps use multiple processes)

**Problem**: "frida-server not found"

**Solution**:
```bash
# Check if it's running
adb shell ps -A | grep frida

# If not, start it
adb shell /data/local/tmp/frida-server &

# If file not found, re-push
adb push frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
```

### mitmproxy Issues

**Problem**: App connects but no traffic shown

**Possible causes**:
1. App ignores global proxy → Need VPN mode or iptables redirect
2. App uses certificate pinning → Expected (test is working!)
3. Wrong proxy host → Use 10.0.2.2:8080 for emulator

**Problem**: Certificate installation fails

**Solution**:
```bash
# Convert cert to different format
openssl x509 -in ~/.mitmproxy/mitmproxy-ca-cert.pem \
  -inform PEM -out mitmproxy-ca-cert.der -outform DER

# Or use the .cer file directly
adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/
```

---

## Version Compatibility Matrix

| Frida | frida-tools | Android API | Notes |
|-------|-------------|-------------|-------|
| 17.7.3 | 17.7.3 | 34-35 | ✅ Tested working |
| 16.x | 16.x | 30-34 | ✅ Should work |
| 15.x | 15.x | 28-33 | ⚠️ Older, but stable |

| mitmproxy | Python | macOS | Linux |
|-----------|--------|-------|-------|
| 12.2.1 | 3.9+ | ✅ Sonoma+ | ✅ Ubuntu 22.04+ |
| 11.x | 3.8+ | ✅ Ventura+ | ✅ Ubuntu 20.04+ |

---

## Quick Reference Commands

```bash
# Start emulator
emulator -avd Pixel_8_Pro_API35_arm &

# Install APK
adb install -r app.apk

# Start app
adb shell am start com.package/.MainActivity

# Start frida-server
adb shell /data/local/tmp/frida-server &

# Hook with Frida (spawn mode)
frida -D emulator-5554 -f com.package -l hook.js

# Hook with Frida (attach mode)
frida -D emulator-5554 -n "AppName" -l hook.js

# List processes
frida-ps -D emulator-5554

# Start tcpdump
adb shell "tcpdump -w /sdcard/capture.pcap" &

# Stop tcpdump
adb shell pkill tcpdump

# Pull capture
adb pull /sdcard/capture.pcap

# Configure proxy
adb shell settings put global http_proxy 10.0.2.2:8080

# Reset proxy
adb shell settings put global http_proxy :0

# Check root availability
adb root  # If fails, emulator is not rooted

# Check app debuggability
adb shell run-as com.package  # If fails, app not debuggable
```

---

## Next Steps After Setup

Once environment is ready:

1. **Verify tools work** with simple tests
2. **Follow Step 7 workflow** in VERIFICATION_CHECKLIST.md
3. **Document findings** in verification report
4. **Save evidence** (pcap files, Frida output, screenshots)

---

**Document Version**: 1.0
**Last Tested**: 2026-02-28
**Platform**: macOS (Sonoma), Android Emulator (API 35)
