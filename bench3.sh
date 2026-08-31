#!/usr/bin/env bash

set -e

ns=(12)
dims=(2 4 6)
deltas=(32 64 128 256 512)
metrics=(0 1 2)

printf "[ProType]  [Assumption]   [Metric] [Dim] [Delta] [Size] [Com.(MB)] [Time(s)]\n"

# Normal
for metric in "${metrics[@]}"; do
  for nn in "${ns[@]}"; do
    for dim in "${dims[@]}"; do
      for delta in "${deltas[@]}"; do
        ./build/fpsi -type 0 -assumption 1 -p "$metric" -nn "$nn" \
          -d "$dim" -delta "$delta" -inter 4 -try 1
      done
      echo
    done
  done
done

# Prefix
for metric in "${metrics[@]}"; do
  for nn in "${ns[@]}"; do
    for dim in "${dims[@]}"; do
      for delta in "${deltas[@]}"; do
        ./build/fpsi -type 0 -assumption 1 -prefix -p "$metric" -nn "$nn" \
          -d "$dim" -delta "$delta" -inter 4 -try 1
      done
      echo
    done
  done
done
