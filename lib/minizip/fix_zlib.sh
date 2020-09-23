#!/bin/bash

for i in *; do
   gsed -i 's/#include \"zlib/#include \"\.\.\/zlib/g' $i
done
