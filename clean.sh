#!/bin/bash

cd kpayload
make clean
cd ..

cd installer
make clean
cd ..

rm -f hen.bin
