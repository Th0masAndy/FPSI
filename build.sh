set -e

apt update
apt install -y build-essential cmake git libtool iproute2 python3 sudo nasm libssl-dev libgmp-dev wget libfmt-dev

cd thirdparty

## Build secure-join
git clone https://github.com/Visa-Research/secure-join.git
cd secure-join
sed -i 's|set(GIT_TAG             "657f6da90bff5774a2d01c824e997572d5e8ba00")|set(GIT_TAG             "d21bc4d7aae941e276b92615252fd1760c902890")|' thirdparty/getLibOTe.cmake
python3 build.py --install=../out/install -D SECUREJOIN_ENABLE_BOOST=ON -D SODIUM_MONTGOMERY=false -D ENABLE_BITPOLYMUL=false 
cd ..
rm -rf secure-join

## Build volePSI
git clone https://github.com/ladnir/volepsi.git
cd volepsi
git checkout 59e06bca81a3287257522cd261bad71e37780642
sed -i 's|36cd7242e085eddba34feaa63733ec4c6ded66c7|d21bc4d7aae941e276b92615252fd1760c902890|g' thirdparty/getLibOTe.cmake
python3 build.py --install=../out/install --sudo --system -DVOLE_PSI_ENABLE_BOOST=true -DVOLE_PSI_ENABLE_BITPOLYMUL=false -DVOLE_PSI_SODIUM_MONTGOMERY=false -DCMAKE_PREFIX_PATH=/usr/local/
cp ./out/build/linux/volePSI/config.h ../out/install/include/volePSI
cd ..
rm -rf volepsi

## Build BLAKE3
git clone https://github.com/BLAKE3-team/BLAKE3.git
cd BLAKE3
git checkout c7f0d216e6fc834b742456b39546c9835baa1277
cmake -S c -B c/build -DCMAKE_INSTALL_PREFIX=../out/install
cmake --build c/build --target install -j
cd ..
rm -rf BLAKE3


cd ..
