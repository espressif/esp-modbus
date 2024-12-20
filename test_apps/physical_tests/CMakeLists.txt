# This is the project CMakeLists.txt file for the test subproject
cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS "$ENV{IDF_PATH}/tools/unit-test-app/components")
list(APPEND EXTRA_COMPONENT_DIRS "../test_common")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(test_modbus_comm_multi_dev)
