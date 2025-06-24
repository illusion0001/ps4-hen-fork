#!/bin/bash

cd kpayload
make clean
cd ..

rm -rf tmp

cd installer
rm include/*.inc
make clean
cd ..

rm -f hen.bin
