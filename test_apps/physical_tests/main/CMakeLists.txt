set(srcs "test_app_main.c" 
            "test_modbus_rs485_comm_master_slave.c"
            "test_modbus_tcp_comm_master_slave.c"
)

# In order for the cases defined by `TEST_CASE` to be linked into the final elf,
idf_component_register(SRCS ${srcs} 
                        PRIV_REQUIRES cmock test_utils test_common unity nvs_flash esp_event esp_eth
                        )

# The workaround for WHOLE_ARCHIVE which is absent in v4.4
set_property(TARGET ${COMPONENT_LIB} APPEND PROPERTY INTERFACE_LINK_LIBRARIES "-u mb_test_include_phys_impl_tcp")
set_property(TARGET ${COMPONENT_LIB} APPEND PROPERTY INTERFACE_LINK_LIBRARIES "-u mb_test_include_phys_impl_serial")

