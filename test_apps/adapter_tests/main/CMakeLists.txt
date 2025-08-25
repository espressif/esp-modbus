set(PROJECT_NAME "test_comm_adapter")

set(srcs "test_app_main.c" 
            "test_modbus_adapter_serial.c"
            "test_modbus_adapter_tcp.c"
)

# In order for the cases defined by `TEST_CASE` to be linked into the final elf,
idf_component_register(SRCS ${srcs} 
                        PRIV_REQUIRES cmock test_common unity test_utils
                        )

set_property(TARGET ${COMPONENT_LIB} APPEND PROPERTY INTERFACE_LINK_LIBRARIES "-u mb_test_include_adapter_impl_serial")
set_property(TARGET ${COMPONENT_LIB} APPEND PROPERTY INTERFACE_LINK_LIBRARIES "-u mb_test_include_adapter_impl_tcp")

# Workaround to avoid static analysis false positives for some components.
if(CONFIG_FMB_COMPILER_STATIC_ANALYZER_ENABLE AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${COMPONENT_LIB} PRIVATE "-fanalyzer")
    message(STATUS "Static analyzer build for ${PROJECT_NAME}.")
endif()