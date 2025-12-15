# Fuzzy PSI

This repository provides the implementation and build scripts for fuzzy private set intersection.

> Note: This project is experimental and primarily intended for research use. Adjust parameters according to your hardware and dataset sizes.

## Requirements

- `cmake`, `make`, `g++ 13`
- Docker (optional, for isolated builds)
- Additional third-party dependencies are installed by `./build.sh`

## Local build

From the project root directory:

```bash
./build.sh    # installs third-party dependencies if needed
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

### Usage examples

Run a basic fuzzy PSI experiment:

```bash
./fpsi -nn 8 -d 8 -delta 16 -v 1
```

Enable prefix optimization:

```bash
./fpsi -nn 8 -d 8 -delta 16 -v 1 -prefix 1
```
