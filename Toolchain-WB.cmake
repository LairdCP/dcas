# this one is important
SET(CMAKE_SYSTEM_NAME Linux)
#this one not so much
SET(CMAKE_SYSTEM_VERSION 1)

# specify the cross compiler
SET(CMAKE_C_COMPILER   /usr/local/arm-laird-linux-gnueabi/bin/arm-laird-linux-gnueabi-gcc)
SET(CMAKE_CXX_COMPILER /usr/local/arm-laird-linux-gnueabi/bin/arm-laird-linux-gnueabi-g++)

# This environment is intended to be setup and run with the dcas directory placed
# in the correct place in the buildroot path, namely packages/lrd/externals/dcas
# And this will find the target environment files
SET(CMAKE_FIND_ROOT_PATH  ../../../../output/wb50n_devel/staging ~/projects/wb_project/wb/buildroot/output/wb50n_devel/staging)
