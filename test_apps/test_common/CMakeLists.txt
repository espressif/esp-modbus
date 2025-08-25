cmake_minimum_required(VERSION 3.22)
idf_component_register(SRCS "test_common.c"
                        INCLUDE_DIRS "include"
                        REQUIRES unity)

set(EXTRA_COMPONENT_DIRS)

if("${IDF_VERSION_MAJOR}.${IDF_VERSION_MINOR}" VERSION_GREATER "5.5")
    list(APPEND EXTRA_COMPONENT_DIRS "$ENV{IDF_PATH}/tools/test_apps/components")
else()
    list(APPEND EXTRA_COMPONENT_DIRS "$ENV{IDF_PATH}/tools/unit-test-app/components")
endif()

add_subdirectory(mb_utest_lib)
target_link_libraries(${COMPONENT_LIB} PUBLIC mb_ut_lib)
