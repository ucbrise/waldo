# libPSI FSS Module Installation Instructions

### Assuming that Relic base is used.
### If you boost.get script from libOTe used to install boost locally, then the script doesn't build and install it, which leads to error when cmake finds it. Follow section 5.1 at https://www.boost.org/doc/libs/1_75_0/more/getting_started/unix-variants.html to make sure it is properly built.

## libOTe
```
git clone --recursive https://github.com/osu-crypto/libOTe.git

cd libOTe

git submodule update --init --recursive

cmake . -DENABLE_RELIC=ON -DBOOST_ROOT="[boost-target-root-dir-absolute-path]" -DBoost_INCLUDE_DIR="[boost-target-root-dir-absolute-path]/include" -DENABLE_NP=ON -DENABLE_KKRT=ON

make -j
```
## libPSI
```
git clone https://github.com/osu-crypto/libPSI.git

cd libPSI

cmake . -DENABLE_RELIC=ON -DBOOST_ROOT="[boost-target-root-dir-absolute-path]" -DBoost_INCLUDE_DIR="[boost-target-root-dir-absolute-path]/include" -DENABLE_DRRN_PSI=ON -DENABLE_KKRT_PSI=ON

make -j
```


