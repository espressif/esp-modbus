set(PROJECT_NAME "modbus_tcp_slave_instances")

idf_component_register(SRCS "tcp_slave_instances.c"
                        INCLUDE_DIRS "."
                        PRIV_REQUIRES  test_utils test_common unity nvs_flash esp_event esp_eth
                        )
