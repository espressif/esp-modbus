set(PROJECT_NAME "modbus_serial_slave")

idf_component_register(SRCS "serial_slave.c"
                    INCLUDE_DIRS ".")
