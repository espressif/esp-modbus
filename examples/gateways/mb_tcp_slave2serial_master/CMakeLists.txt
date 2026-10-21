# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.22)

# Exclude old component freemodbus which exists in old versions
# (keep here just for consistency with other examples).
set(EXCLUDE_COMPONENTS freemodbus)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

set(COMPONENTS main)

project(modbus_tcp2serial_gateway)
