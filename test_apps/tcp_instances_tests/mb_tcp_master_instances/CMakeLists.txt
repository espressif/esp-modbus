# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

# Exclude old component feemodbus which exists in old versions
set(EXCLUDE_COMPONENTS freemodbus)
set(EXTRA_COMPONENT_DIRS "../../test_common")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# The workaround for the test_utils under ESP-IDF v6.0
if("${IDF_VERSION_MAJOR}.${IDF_VERSION_MINOR}" VERSION_GREATER "5.5")
    list(APPEND EXTRA_COMPONENT_DIRS "$ENV{IDF_PATH}/tools/test_apps/components")
else()
    list(APPEND EXTRA_COMPONENT_DIRS "$ENV{IDF_PATH}/tools/unit-test-app/components")
endif()

project(modbus_tcp_master_instances)
