set(srcs "test_app_main.c" 
            "test_mb_controller_unit.c"
)

# In order for the cases defined by `TEST_CASE` to be linked into the final elf,
idf_component_register(SRCS ${srcs} 
                        PRIV_REQUIRES cmock unity test_stubs test_utils mocked_esp_modbus ) #  test_common

# The workaround for WHOLE_ARCHIVE, which is absent in v4.4
set_property(TARGET ${COMPONENT_LIB} APPEND PROPERTY INTERFACE_LINK_LIBRARIES "-u mb_test_include_impl")