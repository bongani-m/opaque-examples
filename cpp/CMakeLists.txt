cmake_minimum_required(VERSION 3.20)
project(opaque_examples CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# OPAQUE_PREFIX holds libopaque + liboprf (built by the top-level Makefile).
set(OPAQUE_PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/prefix" CACHE PATH "libopaque install prefix")

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium>=1.0.19)

find_library(OPAQUE_LIB opaque PATHS "${OPAQUE_PREFIX}/lib" NO_DEFAULT_PATH REQUIRED)
find_library(OPRF_LIB oprf PATHS "${OPAQUE_PREFIX}/lib" NO_DEFAULT_PATH REQUIRED)

add_library(opaque_wrapper INTERFACE)
target_include_directories(opaque_wrapper INTERFACE "${OPAQUE_PREFIX}/include")
target_link_libraries(opaque_wrapper INTERFACE ${OPAQUE_LIB} ${OPRF_LIB} PkgConfig::SODIUM)

add_executable(oprf oprf.cpp)
target_link_libraries(oprf PRIVATE PkgConfig::SODIUM)

add_executable(opaque_flow opaque_flow.cpp)
target_link_libraries(opaque_flow PRIVATE opaque_wrapper)

add_executable(client client.cpp)
target_link_libraries(client PRIVATE opaque_wrapper)

foreach(t oprf opaque_flow client)
  set_target_properties(${t} PROPERTIES BUILD_RPATH "${OPAQUE_PREFIX}/lib")
endforeach()
