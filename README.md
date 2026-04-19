# Efficient Fuzzy PSI under One-Sided Assumptions

This repository provides the implementation and build scripts for fuzzy private set intersection.

> Note: This project is experimental and primarily intended for research use. Adjust parameters according to your hardware and dataset sizes.

## Location of Main Functionality
- `src/*.cpp` contains the implementations of our building blocks such as `so-OPPRF`, `ConSel`, `ConRand` and other MPC components
- `src/fpsi_low.cpp` contains the implementations of protocols under unique cell/block assumption
- `src/fpsi_low_prefix.cpp` contains the implementations of the prefix-optimized protocol

## Requirements

- Linux on **AMD64** Only
- `cmake`, `make`, `g++ 13`
- Docker (optional, for isolated builds)
- Additional third-party libraries [secure-join](https://github.com/Visa-Research/secure-join.git) and [volePSI](https://github.com/ladnir/volepsi.git) (can be installed by the script [build.sh](./build.sh))


- **Dependencies :**

```bash
build-essential
cmake
git 
libtool 
iproute2 
python3 
sudo 
nasm 
libssl-dev 
libgmp-dev 
wget 
libfmt-dev
```

## Local build

From the project root directory:

```bash
./build.sh    # installs third-party dependencies if needed (about 10-15 mins)
mkdir -p build && cd build
cmake ..
make -j

# The executable will be located at ./build/fpsi
```

## Docker (optional)

Use Docker for an isolated or reproducible build environment:

```bash
docker build -t <your-image-name> .
docker run -it --name <your-container-name> --cap-add=NET_ADMIN --memory=512g <your-image-name>
docker exec -it <your-container-name> bash
```

## Executable: `./build/fpsi`

Below are the commonly used command-line flags. Flags use a leading dash (for example `-nn`, `-d`).

| Flag | Meaning | Values / Notes |
|---|---|---|
| `-d` | Dimension | integer |
| `-p` | Metric | `0`: $L_\infty$ (default), `1`: $L_1$, `2`: $L_2$ |
| `-delta` | Distance threshold (δ) | recommended to be a power of 2 |
| `-nn` | log2 of input set size | tested values: `8`~`16` |
| `-v` | Verbosity | `0`: off (default), `1`: info |
| `-try` | Number of runs | integer, default `1` |
| `-prefix` | Prefix optimization flag | `0`: off (default), `1`: on |
| `-assumption` | Assumption | `0`: unique cell, `1`: unique block |

### Usage examples

Run a basic fuzzy PSI experiment:

```bash
./fpsi -nn 8 -d 8 -delta 16 -v 1 -assumption 1
```

Enable prefix optimization:

```bash
./fpsi -nn 8 -d 8 -delta 16 -v 1 -prefix -assumption 1
```
