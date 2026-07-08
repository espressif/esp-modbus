set(PROJECT "test_bcast")

set(srcs "test_app_main.c"
            "${PROJECT}_serial.c"
)

idf_component_register(SRCS ${srcs}
                        PRIV_REQUIRES test_utils test_common unity
                        )

# The workaround for WHOLE_ARCHIVE which is absent in v4.4
set_property(TARGET ${COMPONENT_LIB} APPEND PROPERTY INTERFACE_LINK_LIBRARIES "-u mb_test_include_bcast_serial")

# Workaround to avoid static analysis false positives for some components.
if(CONFIG_FMB_COMPILER_STATIC_ANALYZER_ENABLE AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${COMPONENT_LIB} PRIVATE "-fanalyzer")
    message(STATUS "Static analyzer build for ${PROJECT_NAME}.")
endif()
