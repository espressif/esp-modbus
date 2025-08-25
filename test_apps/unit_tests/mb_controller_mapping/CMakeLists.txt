# This is the project CMakeLists.txt file for the test subproject
cmake_minimum_required(VERSION 3.22)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

set(EXTRA_COMPONENT_DIRS "../../test_common" "../test_stubs")

# The workaround for the test_utils under ESP-IDF v6.0
if("${IDF_VERSION_MAJOR}.${IDF_VERSION_MINOR}" VERSION_GREATER "5.5")
    list(APPEND EXTRA_COMPONENT_DIRS "$ENV{IDF_PATH}/tools/test_apps/components")
else()
    list(APPEND EXTRA_COMPONENT_DIRS "$ENV{IDF_PATH}/tools/unit-test-app/components")
endif()

set(COMPONENTS driver esp_timer esp_event esp_netif main)

# list(APPEND EXTRA_COMPONENT_DIRS
#      "$ENV{IDF_PATH}/tools/mocks/lwip/"
#      "$ENV{IDF_PATH}/tools/mocks/freertos/"
#      "$ENV{IDF_PATH}/tools/mocks/esp_timer/"
#     )

project(test_mb_controller_mapping_unit)
