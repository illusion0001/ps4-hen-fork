#!/bin/bash
set -e

# Only update/install if running as root AND on Ubuntu
# This is for the CI
# On your system you shouldn't be running as root and should already have these installed
if [ "$(id -u)" -eq 0 ] && grep -qi ubuntu /etc/os-release; then
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl unzip xxd
fi

cd kpayload
make
cd ..

mkdir -p tmp
cd tmp
curl -fLJO https://github.com/Scene-Collective/ps4-hen-plugins/releases/latest/download/plugins.zip
unzip plugins.zip
for file in *.prx; do xxd -i "$file" > "../installer/include/${file}.inc"; done
cd ..
rm -rf tmp

cd installer
make
cd ..

rm -f hen.bin
cp installer/installer.bin hen.bin
