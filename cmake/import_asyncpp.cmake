if(TARGET asyncpp)
  message(STATUS "Using existing asyncpp target.")
else()
  message(STATUS "Missing asyncpp, using Fetch to import it.")

  include(FetchContent)
  FetchContent_Declare(asyncpp
                       GIT_REPOSITORY "https://github.com/asyncpp/asyncpp.git")
  FetchContent_MakeAvailable(asyncpp)
endif()
