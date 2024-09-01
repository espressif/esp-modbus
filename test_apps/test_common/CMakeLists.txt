cmake_minimum_required(VERSION 3.16)
idf_component_register(SRCS "test_common.c"
                        INCLUDE_DIRS "include"
                        REQUIRES unity)

set(EXTRA_COMPONENT_DIRS "$ENV{IDF_PATH}/tools/unit-test-app/components") 

add_subdirectory(mb_utest_lib)
target_link_libraries(${COMPONENT_LIB} PUBLIC mb_ut_lib)
