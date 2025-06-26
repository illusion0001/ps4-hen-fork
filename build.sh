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
make clean
make
cd ..

mkdir -p tmp
cd tmp

# known bundled plugins
PRX_FILES="plugin_bootloader.prx plugin_loader.prx plugin_server.prx"

SKIP_DOWNLOAD=false
if [ -f plugins.zip ]; then
  SKIP_DOWNLOAD=true
else
  for prx in "${PRX_FILES[@]}"; do
    if [ -f "$prx" ]; then
      SKIP_DOWNLOAD=true
      break
    fi
  done
fi

if [ "$SKIP_DOWNLOAD" = false ]; then
  f="plugins.zip"
  rm -f $f
  curl -fLJO https://github.com/Scene-Collective/ps4-hen-plugins/releases/latest/download/$f
  unzip $f
fi

# need to use translation units to force rebuilds
# including as headers doesn't do it
for file in *.prx; do
  echo $file
  xxd -i "$file" | sed 's/^unsigned /static const unsigned /' > "../installer/source/${file}.inc.c"
done

cd ..

cd installer
make clean
make
cd ..

rm -f hen.bin
cp installer/installer.bin hen.bin
