# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.5)

# The workaround to expliciply remove the component from dependency list.
# This should allow to avoid GNU static analizer warnings for the esp_http_server component.
set(EXCLUDE_COMPONENTS esp_http_server)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(mb_serial_cpp)


