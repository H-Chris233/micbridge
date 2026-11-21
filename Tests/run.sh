#!/bin/zsh
set -euo pipefail
cd "${0:A:h:h}"
arch=$(uname -m)
version=0.20261105.0
if [[ ! -f "build/boringssl/$version-$arch/libcrypto.a" ]]; then ./build.sh; fi
sdk=$(xcrun --sdk macosx --show-sdk-path)
tmp=$(mktemp -d "$PWD/build/.tests.XXXXXXXX")
trap 'rm -rf "$tmp"' EXIT
xcrun clang -target "$arch-apple-macos14.2" -isysroot "$sdk" -O2 -Werror \
  -I "build/boringssl/source-$version/include" -c Sources/BridgeCrypto.c -o "$tmp/crypto.o"
xcrun clang -target "$arch-apple-macos14.2" -isysroot "$sdk" -O2 -Werror -fobjc-arc \
  -c Sources/ChannelBinding.m -o "$tmp/binding.o"
xcrun swiftc -warnings-as-errors -O -swift-version 5 -target "$arch-apple-macos14.2" -sdk "$sdk" \
  -import-objc-header Sources/BridgeCrypto.h Sources/SecureProtocol.swift Sources/PairingStore.swift \
  Tests/SecureProtocolTests.swift "$tmp/crypto.o" "$tmp/binding.o" \
  "build/boringssl/$version-$arch/libcrypto.a" -lc++ -o "$tmp/tests"
"$tmp/tests"
