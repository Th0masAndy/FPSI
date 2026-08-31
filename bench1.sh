#!/usr/bin/env bash

set -e

ns=(8 12 16)
dims=(4 8 16)
deltas=(16 32)
metrics=(0 1 2)

printf "[ProType]  [Assumption]   [Metric] [Dim] [Delta] [Size] [Com.(MB)] [Time(s)]\n"

for metric in "${metrics[@]}"; do
  for nn in "${ns[@]}"; do
    for dim in "${dims[@]}"; do
      for delta in "${deltas[@]}"; do
        ./build/fpsi -type 1 -p "$metric" -nn "$nn" -d "$dim" \
          -delta "$delta" -inter 4 -try 1
      done
      echo
    done
  done
done

prefix_ns=(12)
prefix_dims=(8)
prefix_deltas=(16 64 256 1024)

for metric in "${metrics[@]}"; do
  for nn in "${prefix_ns[@]}"; do
    for dim in "${prefix_dims[@]}"; do
      for delta in "${prefix_deltas[@]}"; do
        ./build/fpsi -type 1 -prefix -p "$metric" -nn "$nn" -d "$dim" \
          -delta "$delta" -inter 4 -try 1 
      done
      echo
    done
  done
done
