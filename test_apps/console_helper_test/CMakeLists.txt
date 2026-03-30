# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.22)

set(EXCLUDE_COMPONENTS freemodbus)
list(APPEND EXTRA_COMPONENT_DIRS "../../components/mb_console_helper")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(modbus_console_helper_test)
