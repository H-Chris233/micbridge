#!/bin/zsh
# Build universal, locally signed apps without installing or starting them.
set -euo pipefail
cd "${0:A:h}"
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
mkdir -p build

version=0.20261105.0
digest=2df2b287f3406a3d2f7f51dccb82cffbddf6cf981811e8edcfffe8fbf02c3ac4
dep="$PWD/build/boringssl"
archive="$dep/$version.tar.gz"
source_dir="$dep/source-$version"
cmake_bin=${CMAKE:-cmake}
command -v "$cmake_bin" >/dev/null || { print -u2 'CMake 3.22+ is required (brew install cmake).'; exit 1; }
mkdir -p "$dep"
staging=$(mktemp -d "$PWD/build/.staging.XXXXXXXX")
trap 'rm -rf "$staging"' EXIT
verify_archive() { printf '%s  %s\n' "$digest" "$1" | shasum -a 256 -c -; }
if [[ ! -f "$archive" ]]; then
  curl --fail --location --retry 2 \
    "https://github.com/google/boringssl/releases/download/$version/boringssl-$version.tar.gz" \
    -o "$staging/boringssl.tar.gz"
  verify_archive "$staging/boringssl.tar.gz"
  mv "$staging/boringssl.tar.gz" "$archive"
else
  verify_archive "$archive"
fi
if [[ ! -d "$source_dir" ]]; then
  mkdir "$staging/boringssl"
  tar -xzf "$archive" --strip-components=1 -C "$staging/boringssl"
  mv "$staging/boringssl" "$source_dir"
fi
sdk=$(xcrun --sdk macosx --show-sdk-path)
shared=(Sources/SecureProtocol.swift Sources/PairingStore.swift Sources/MenuBar.swift)
for arch in arm64 x86_64; do
  obj="$dep/$version-$arch"
  "$cmake_bin" -S "$source_dir" -B "$obj" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_ARCHITECTURES="$arch" -DCMAKE_OSX_DEPLOYMENT_TARGET=14.2 \
    -DCMAKE_OSX_SYSROOT="$sdk" -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF
  "$cmake_bin" --build "$obj" --target crypto --parallel "$(sysctl -n hw.logicalcpu)"
  xcrun clang -target "$arch-apple-macos14.2" -isysroot "$sdk" -O2 -Werror \
    -I "$source_dir/include" -c Sources/BridgeCrypto.c -o "$staging/crypto-$arch.o"
  xcrun clang -target "$arch-apple-macos14.2" -isysroot "$sdk" -O2 -Werror -fobjc-arc \
    -c Sources/ChannelBinding.m -o "$staging/binding-$arch.o"
done

make_app() {
  local name=$1 src=$2 exe=$3 bundle="$staging/$1.app" arch
  mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
  cp "$source_dir/LICENSE" "$bundle/Contents/Resources/BoringSSL-LICENSE.txt"
  cat > "$bundle/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>local.micbridge.$exe</string>
  <key>CFBundleName</key><string>$name</string>
  <key>CFBundleExecutable</key><string>$exe</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>2.0</string>
  <key>LSMinimumSystemVersion</key><string>14.2</string>
  <key>LSUIElement</key><true/>
  <key>NSMicrophoneUsageDescription</key><string>MicBridge streams this Mac's microphone to your paired Mac.</string>
  <key>NSLocalNetworkUsageDescription</key><string>MicBridge connects your two Macs over the local network.</string>
  <key>NSBonjourServices</key><array><string>_micbridge-v2._tcp</string></array>
</dict></plist>
PLIST
  for arch in arm64 x86_64; do
    xcrun swiftc -warnings-as-errors -O -swift-version 5 -target "$arch-apple-macos14.2" -sdk "$sdk" \
      -import-objc-header Sources/BridgeCrypto.h "${shared[@]}" "Sources/$src" \
      "$staging/crypto-$arch.o" "$staging/binding-$arch.o" "$dep/$version-$arch/libcrypto.a" -lc++ -o "$staging/$exe-$arch"
  done
  lipo -create "$staging/$exe-arm64" "$staging/$exe-x86_64" -output "$bundle/Contents/MacOS/$exe"
  codesign --force --sign - "$bundle"
  codesign --verify --strict "$bundle"
}

make_app MicBridgeSender Sender.swift micbridge-sender
make_app MicBridgeReceiver Receiver.swift micbridge-receiver
for app in MicBridgeSender MicBridgeReceiver; do
  rm -rf "build/$app.app"
  mv "$staging/$app.app" "build/$app.app"
  echo "built build/$app.app"
done
