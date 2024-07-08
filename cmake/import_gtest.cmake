enable_testing()
include(GoogleTest)

if(TARGET GTest::gtest)
  message(STATUS "Using existing GTest::gtest target.")
else()
  if(HUNTER_ENABLED)
    hunter_add_package(GTest)
    find_package(GTest CONFIG REQUIRED)
  else()
    include(FetchContent)
    FetchContent_Declare(
      googletest
      GIT_REPOSITORY https://github.com/google/googletest.git
      GIT_TAG release-1.12.1)
    if(WIN32)
      set(gtest_force_shared_crt
          ON
          CACHE BOOL "" FORCE)
      set(BUILD_GMOCK
          OFF
          CACHE BOOL "" FORCE)
    endif()
    FetchContent_MakeAvailable(googletest)
  endif()
endif()
