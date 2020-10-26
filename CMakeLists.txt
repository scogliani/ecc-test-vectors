cmake_minimum_required(VERSION 3.2)

# set the project name and version
project(ecc_test_vectors
        VERSION 1.0
        LANGUAGES C)

include(ExternalProject)

set(PROJECT_OPENSSL openssl)

ExternalProject_Add(${PROJECT_OPENSSL}
    PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/${PROJECT_OPENSSL}

    GIT_REPOSITORY https://github.com/openssl/openssl
    GIT_TAG OpenSSL_1_0_2h

    UPDATE_COMMAND ""
    CMAKE_COMMAND ""
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND "./config"
    BUILD_COMMAND ${MAKE}
    TEST_BEFORE_INSTALL 1
    INSTALL_COMMAND ""
)

ExternalProject_Get_Property(${PROJECT_OPENSSL} PREFIX)
set(INSTALL_DIR_OPENSSL ${PREFIX})

set(REG_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
set(REG_INC "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")

# Optionally glob, but only for CMake 3.12 or later:
file(GLOB_RECURSE INC CONFIGURE_DEPENDS "${REG_INC}")

# Make an automatic library - will be static or dynamic based on user setting
file(GLOB_RECURSE SRC CONFIGURE_DEPENDS "${REG_SRC}")

# add the executable
add_executable(${PROJECT_NAME} ${SRC} ${INC})

add_dependencies(${PROJECT_NAME} ${PROJECT_OPENSSL})

# We need this directory, and users of our library will need it too
target_include_directories(${PROJECT_NAME} PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${INSTALL_DIR_OPENSSL}/src"
    "${INSTALL_DIR_OPENSSL}/src/openssl/include")

# set the compile options
set(CMAKE_C_FLAGS "-g -ansi -std=c11 -Wall -Wextra -Wpedantic -Wconversion")

target_compile_definitions(${PROJECT_NAME} PUBLIC "ECDH")

# Linking the libraries to the executable
target_link_libraries(${PROJECT_NAME} PRIVATE "ssl" "crypto")
target_link_libraries(${PROJECT_NAME} PUBLIC "dl")
