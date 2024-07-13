cmake_minimum_required(VERSION 3.15)

project(AsyncppIO)
find_package(Threads REQUIRED)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(ASYNCPP_ENABLE_URING_DEFAULT ON)
else()
  set(ASYNCPP_ENABLE_URING_DEFAULT OFF)
endif()

option(ASYNCPP_BUILD_TEST "Enable test builds" ON)
option(ASYNCPP_WITH_ASAN "Enable asan for test builds" ON)
option(ASYNCPP_ENABLE_URING "Enable support for linux uring"
       ${ASYNCPP_ENABLE_URING_DEFAULT})
include(cmake/import_openssl.cmake)
include(cmake/import_asyncpp.cmake)

if(ASYNCPP_ENABLE_URING)
  find_package(PkgConfig REQUIRED)
  if(HUNTER_ENABLED)
    # Workaround hunter hideing system libs
    set(HUNTER_LIBPATH $ENV{PKG_CONFIG_LIBDIR})
    unset(ENV{PKG_CONFIG_LIBDIR})
    pkg_search_module(URING REQUIRED NO_CMAKE_PATH liburing uring)
    set(ENV{PKG_CONFIG_LIBDIR} ${HUNTER_LIBPATH})
  else()
    pkg_search_module(URING REQUIRED NO_CMAKE_PATH liburing uring)
  endif()
endif()

add_library(
  asyncpp_io
  ${CMAKE_CURRENT_SOURCE_DIR}/src/address.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/dns.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/file.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/io_engine_generic_unix.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/io_engine_select.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/io_engine_uring.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/io_engine_iocp.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/io_engine.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/io_service.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/socket.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/tls.cpp)
target_link_libraries(asyncpp_io PUBLIC asyncpp OpenSSL::SSL Threads::Threads)
if(WIN32)
  target_link_libraries(asyncpp_io PUBLIC wsock32 ws2_32 ntdll)
endif()
target_include_directories(asyncpp_io
                           PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(asyncpp_io PUBLIC cxx_std_20)

if(ASYNCPP_ENABLE_URING)
  target_link_libraries(asyncpp_io PRIVATE ${URING_LINK_LIBRARIES})
  target_include_directories(asyncpp_io PRIVATE ${URING_INCLUDE_DIRS})
  target_compile_definitions(asyncpp_io PRIVATE ASYNCPP_ENABLE_URING=1)
endif()

if(ASYNCPP_WITH_ASAN)
  if(MSVC)
    target_compile_options(asyncpp_io PRIVATE -fsanitize=address /Zi)
    target_compile_definitions(asyncpp_io PRIVATE _DISABLE_VECTOR_ANNOTATION)
    target_compile_definitions(asyncpp_io PRIVATE _DISABLE_STRING_ANNOTATION)
    target_link_libraries(asyncpp_io PRIVATE libsancov.lib)
  else()
    target_compile_options(asyncpp_io PRIVATE -fsanitize=address)
    target_link_libraries(asyncpp_io PRIVATE asan)
  endif()
endif()

# G++ below 11 needs a flag
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "11.0")
    target_compile_options(asyncpp_io PUBLIC -fcoroutines)
  endif()
endif()

if(ASYNCPP_BUILD_TEST)
  include(cmake/import_gtest.cmake)

  add_executable(
    asyncpp_io-test
    ${CMAKE_CURRENT_SOURCE_DIR}/test/address.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test/dns.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test/endpoint.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test/file.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test/network.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test/so_compat.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test/socket.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test/tls.cpp)
  target_link_libraries(
    asyncpp_io-test PRIVATE asyncpp_io GTest::gtest GTest::gtest_main
                            Threads::Threads)

  if(ASYNCPP_WITH_ASAN)
    message(STATUS "Building with asan enabled")

    if(MSVC)
      target_compile_options(asyncpp_io-test PRIVATE -fsanitize=address /Zi)
      target_compile_definitions(asyncpp_io-test
                                 PRIVATE _DISABLE_VECTOR_ANNOTATION)
      target_compile_definitions(asyncpp_io-test
                                 PRIVATE _DISABLE_STRING_ANNOTATION)
      target_link_libraries(asyncpp_io-test PRIVATE libsancov.lib)
    else()
      target_compile_options(asyncpp_io-test PRIVATE -fsanitize=address)
      target_link_libraries(asyncpp_io-test PRIVATE asan)
    endif()
  endif()

  gtest_discover_tests(asyncpp_io-test)
endif()
