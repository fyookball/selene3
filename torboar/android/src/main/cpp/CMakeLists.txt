cmake_minimum_required(VERSION 3.10.2)
project(torboar_native C CXX)

# ------------------------------------------------------------
# Global include path (needed for internal .h in src/)
# ------------------------------------------------------------
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1
    ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/include
    ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/src
)

# ------------------------------------------------------------
# Configure flags equivalent to Electron Cash ./configure
# ------------------------------------------------------------
add_definitions(
    -DENABLE_MODULE_SCHNORR=1
    -DENABLE_MODULE_ECDH=1
    -DENABLE_MODULE_RECOVERY=1
    -DENABLE_MODULE_EXPERIMENTAL=1

    -DUSE_NUM_NONE=1
    -DUSE_FIELD_10X26=1
    -DUSE_SCALAR_8X32=1
    -DUSE_FIELD_INV_BUILTIN=1
    -DUSE_SCALAR_INV_BUILTIN=1
)

# ------------------------------------------------------------
# Build the secp256k1 shared library (core C implementation)
# ------------------------------------------------------------
add_library(secp256k1 SHARED
    secp256k1/src/secp256k1.c
)

# ------------------------------------------------------------
# JNI bridge that wraps secp256k1 for Java access
# ------------------------------------------------------------
add_library(secp256k1_jni SHARED
    secp256k1_jni.cpp
)

target_include_directories(secp256k1_jni PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1
    ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/include
    ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/src
)

target_link_libraries(secp256k1_jni
    secp256k1
    android
    log
)

