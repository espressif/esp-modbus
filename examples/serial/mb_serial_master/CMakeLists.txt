# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

# Exclude old component feemodbus which exists in old versions
set(EXCLUDE_COMPONENTS freemodbus)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(modbus_serial_master)
