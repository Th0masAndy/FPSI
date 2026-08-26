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

Below are the commonly used command-line flags. Flags use a leading dash (for example `-nn`, `-d`).

| Flag | Meaning | Values / Notes |
|---|---|---|
| `-d` | Dimension | integer |
| `-p` | Metric | `0`: $L_\infty$ (default), `1`: $L_1$, `2`: $L_2$ |
| `-delta` | Distance threshold (δ) | recommended to be a power of 2 |
| `-nn` | log2 of input set size (n) | tested values: `8`~`16` |
| `-v` | Verbosity | `0`: off (default), `1`: info |
| `-try` | Number of runs | integer, default `1` |
| `-prefix` | Prefix optimization flag | `0`: off (default), `1`: on |
| `-assumption` | Assumption | `0`: unique cell, `1`: unique block |

## Usage Examples

Run a basic fuzzy PSI experiment:

```bash
./fpsi -nn 8 -d 8 -delta 16 -v 1 -assumption 1
```

Enable prefix optimization:

```bash
./fpsi -nn 8 -d 8 -delta 16 -v 1 -prefix -assumption 1
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
