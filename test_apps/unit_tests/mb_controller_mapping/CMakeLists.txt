# This is the project CMakeLists.txt file for the test subproject
cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS "$ENV{IDF_PATH}/tools/unit-test-app/components")
list(APPEND EXTRA_COMPONENT_DIRS "../../test_common")
list(APPEND EXTRA_COMPONENT_DIRS "../test_stubs")

#set(COMPONENTS driver esp_timer esp_event esp_netif main)

# list(APPEND EXTRA_COMPONENT_DIRS
#      "$ENV{IDF_PATH}/tools/mocks/lwip/"
#      "$ENV{IDF_PATH}/tools/mocks/freertos/"
#      "$ENV{IDF_PATH}/tools/mocks/esp_timer/"
#     )

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(test_mb_controller_mapping_unit)
