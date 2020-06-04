cmake_minimum_required(VERSION 2.8.2)

foreach(test test_grpc)

  set(${test}_SRCS ${test}.cpp)

  # Executable
  set(executable_name ${test})
  add_executable(${executable_name} ${${test}_SRCS})
  target_link_libraries(${executable_name} grpc)

  # Add as unit test
  add_test(NAME ${test} COMMAND ${executable_name})

endforeach()