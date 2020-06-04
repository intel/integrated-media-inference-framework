cmake_minimum_required(VERSION 2.8.2)

foreach(test test_broker_subscribe test_broker_socket_thread)

  set(${test}_SRCS ${test}.cpp ../src/broker_server.cpp)

  # Executable
  set(executable_name ${test})
  add_executable(${executable_name} ${${test}_SRCS})
  target_link_libraries(${executable_name} imif_common)

  # Add as unit test
  add_test(NAME ${test} COMMAND ${executable_name})

endforeach()
