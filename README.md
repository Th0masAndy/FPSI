# FPSI
FPSI implements fuzzy matching for two private sets. It includes the two-sided assumption protocol [S\&P'26](https://ieeexplore.ieee.org/abstract/document/11573503) and the one-sided assumption protocol [CCS'26](https://arxiv.org/abs/2608.17770). 


> Note: This project is experimental and primarily intended for research use. Adjust parameters according to your hardware and dataset sizes.

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

## Command-line Options

All command-line option names are lowercase. Run the built-in help for the complete description:

```bash
./build/fpsi -h
```

| Flag | Meaning | Values / Notes |
|---|---|---|
| `-type` | Protocol | `0`: one-sided (default), `1`: two-sided |
| `-p` | Distance metric | `0`: $L_\infty$ (default), `1`: $L_1$, `2`: $L_2$ |
| `-assumption` | One-sided assumption | `0`: unique cell (default), `1`: unique block |
| `-prefix` | Prefix optimization | flag; when enabled, `delta` must be a power of two |
| `-sender` | One-sided protocol direction | flag; use the sender-sided protocol |
| `-n` | Input set size | integer |
| `-nn` | log2 of input set size | default `10`; tested values: `8`–`16` |
| `-d` | Dimension | integer, default `2` |
| `-delta` | Distance threshold | integer, default `2` |
| `-inter` | Planted intersection size | integer |
| `-try` | Number of benchmark runs | integer, default `1` |
| `-v` | Verbose output | `0`: off (default), `1`: on |
| `-s` | Prefix shift | integer, default `0` |
| `-h`, `--help` | Help | print options and exit |

## Usage Examples

Run the default one-sided protocol:

```bash
./build/fpsi -type 0 -p 0 -nn 8 -d 8 -delta 16 -v 1
```

Run the two-sided protocol:

```bash
./build/fpsi -type 1 -p 2 -nn 8 -d 8 -delta 16
```

Enable prefix optimization:

```bash
./build/fpsi -type 0 -p 0 -nn 8 -d 8 -delta 16 -prefix
```

------------------------------------------------------------------------

## Baseline Implementations

The following baseline implementations are used for comparison.

### Gao et al. 
[Code](https://github.com/ql70ql70/Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping) |   [Paper](https://eprint.iacr.org/2024/1462)

Recommended Docker image:

    blueobsidian/gao_artifact:latest

------------------------------------------------------------------------

### Dang et al.

[Code](https://github.com/zhouxv/ourFuzzyPSI-C) | [Paper](https://eprint.iacr.org/2025/1796)

Recommended Docker image:

    blueobsidian/fpsi_artifact:latest

------------------------------------------------------------------------

## Acknowledgements
Parts of this codebase (for prefix optimization) are adapted from [zhouxv/ourFuzzyPSI-C](https://github.com/zhouxv/ourFuzzyPSI-C)


## Citation

If you make use of our work, please consider citing us:

```bibtex
@INPROCEEDINGS{
  title={Efficient fuzzy private set intersection from secret-shared OPRF},
  author={Yang, Xinpeng and Hao, Meng and Weng, Chenkai and Deng, Robert H and Wen, Yonggang and Zhang, Tianwei},
  booktitle={2026 IEEE Symposium on Security and Privacy (SP)},
  pages={2442--2461},
  year={2026},
  organization={IEEE}
}

@article{yang2026efficient,
  title={Efficient Fuzzy PSI under One-Sided Assumptions},
  author={Yang, Xinpeng and Hao, Meng and Jia, Yanxue and Weng, Chenkai and Wen, Yonggang and Zhang, Tianwei},
  journal={arXiv preprint arXiv:2608.17770},
  year={2026}
}
```
