cmake_minimum_required(VERSION 3.20)
project(emv_auth_host C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(EAH_SANITIZE "Build with ASan + UBSan" OFF)
option(EAH_FUZZ "Build libFuzzer targets (clang only)" OFF)
set(EAH_DEPS_ROOT "" CACHE PATH "Unpacked .deb root for headers/libs (local builds without sudo)")

if(EAH_DEPS_ROOT)
  list(PREPEND CMAKE_PREFIX_PATH "${EAH_DEPS_ROOT}/usr")
endif()
find_package(OpenSSL 3 REQUIRED)
find_package(SQLite3 REQUIRED)

set(WARN -Wall -Wextra -Wshadow -Wformat=2 -Wconversion -Wno-sign-conversion)
add_compile_options(-fstack-protector-strong)
if(NOT EAH_SANITIZE AND NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_definitions(_FORTIFY_SOURCE=2)
endif()
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_link_options(-Wl,-z,relro,-z,now -pie)

if(EAH_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
  add_link_options(-fsanitize=address,undefined)
endif()

# The DDL lives in sql/schema.sql and is compiled into the binary.
file(READ ${CMAKE_SOURCE_DIR}/sql/schema.sql EAH_SCHEMA)
configure_file(src/schema.cpp.in ${CMAKE_BINARY_DIR}/schema.cpp @ONLY)

# C99 wire codecs.
add_library(eahwire STATIC c/iso8583.c c/tlv.c)
target_include_directories(eahwire PUBLIC c)
target_compile_options(eahwire PRIVATE ${WARN} -Wstrict-prototypes)

add_library(eahcore STATIC
  src/emv_crypto.cpp src/pan.cpp src/db.cpp src/msg.cpp src/auth.cpp src/simcard.cpp
  ${CMAKE_BINARY_DIR}/schema.cpp)
target_include_directories(eahcore PUBLIC src)
target_link_libraries(eahcore PUBLIC eahwire OpenSSL::Crypto SQLite::SQLite3)
target_compile_options(eahcore PRIVATE ${WARN})

add_executable(eah-server src/server_main.cpp)
add_executable(eah-admin tools/admin.cpp)
add_executable(termsim tools/termsim.cpp)
add_executable(unit_tests tests/unit_tests.cpp)
foreach(t eah-server eah-admin termsim unit_tests)
  target_link_libraries(${t} PRIVATE eahcore)
  target_compile_options(${t} PRIVATE ${WARN})
endforeach()
target_link_libraries(termsim PRIVATE pthread)

if(EAH_FUZZ)
  foreach(f fuzz_iso8583 fuzz_tlv)
    add_executable(${f} fuzz/${f}.c)
    target_link_libraries(${f} PRIVATE eahwire)
    target_compile_options(${f} PRIVATE -fsanitize=fuzzer)
    target_link_options(${f} PRIVATE -fsanitize=fuzzer)
  endforeach()
  add_executable(fuzz_engine fuzz/fuzz_engine.cpp)
  target_link_libraries(fuzz_engine PRIVATE eahcore)
  target_compile_options(fuzz_engine PRIVATE -fsanitize=fuzzer)
  target_link_options(fuzz_engine PRIVATE -fsanitize=fuzzer)
  # Coverage feedback for the code under test, not just the harness.
  target_compile_options(eahwire PRIVATE -fsanitize=fuzzer-no-link)
  target_compile_options(eahcore PRIVATE -fsanitize=fuzzer-no-link)
endif()
