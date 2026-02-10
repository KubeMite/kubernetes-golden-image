#!/bin/bash
# This script sets up the dev container with needed utilities
# This script assumes an alpine-linux environment
# This script works with both arm and x86 architecture, and with both glibc and musl linux standard library
# This script checks the sha256 of the donwloaded file before extracting it

apk add curl jq unzip

ZIP_FILE_NAME="bws.zip"
HASH_FILE_NAME="bws-sha256-checksums.txt"

# Put requested version here if a specific version is required (without the v in the tag name)
REQUESTED_VERSION=""
CURRENT_TAG="$(curl -Ss --request GET https://api.github.com/repos/bitwarden/sdk-sm/releases?per_page=100 | jq --raw-output '[.[] | select(.draft == false) | select(.prerelease == false) | select(.tag_name | startswith("bws-")) | .tag_name][0]')"
CURRENT_VERSION="${CURRENT_TAG#bws-v}"
VERSION="${REQUESTED_VERSION:-$CURRENT_VERSION}"

if getconf GNU_LIBC_VERSION &> /dev/null; then
  LINUX_STANDARD_LIBRARY="gnu"
else
  LINUX_STANDARD_LIBRARY="musl"
fi

curl -SsL "https://github.com/bitwarden/sdk-sm/releases/download/bws-v$VERSION/bws-$(uname -m)-unknown-linux-$LINUX_STANDARD_LIBRARY-$VERSION.zip" -o "$ZIP_FILE_NAME"
curl -SsL "https://github.com/bitwarden/sdk-sm/releases/download/bws-v$VERSION/bws-sha256-checksums-$VERSION.txt" -o "$HASH_FILE_NAME"

sed -i "s/bws-$(uname -m)-unknown-linux-$LINUX_STANDARD_LIBRARY-$VERSION.zip/$ZIP_FILE_NAME/" "$HASH_FILE_NAME"

if ! grep "$ZIP_FILE_NAME" "$HASH_FILE_NAME" | sha256sum -c; then
  echo "File hash doesnt match expected result"
  exit 1
fi

unzip "$ZIP_FILE_NAME"

rm "$ZIP_FILE_NAME" "$HASH_FILE_NAME"

mv bws /usr/local/bin
chmod +x /usr/local/bin/bws