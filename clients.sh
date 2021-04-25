#!/bin/bash

n=$1
for ((i=0; i<n; i++)); do
	./aether c 127.0.0.1 3443 &
done
wait
