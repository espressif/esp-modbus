cmake_minimum_required(VERSION 3.16)
set(srcs "src/mb_object_stub.c")

idf_component_register( SRCS ${srcs}
                        INCLUDE_DIRS "include"
                        REQUIRES test_common unity)
