#!/bin/bash
set -e

# These are used beloe
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl unzip xxd

cd kpayload
make
cd ..

mkdir -p tmp
cd tmp
curl -fLJO https://github.com/illusion0001/ps4-hen-plugins/releases/latest/download/plugins.zip
unzip plugins.zip
for file in *.prx; do xxd -i "$file" > "../installer/include/${file}.inc"; done
cd ..

cd installer
make
cd ..

rm -f hen.bin
cp installer/installer.bin hen.bin
