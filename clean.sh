#!/bin/bash

cd kpayload
make clean
cd ..

rm -rf tmp

cd installer
make clean
cd ..

rm -f hen.bin
