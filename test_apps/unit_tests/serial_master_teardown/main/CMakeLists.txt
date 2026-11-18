set(modbus_dir "${CMAKE_CURRENT_LIST_DIR}/../../../..")
get_filename_component(modbus_dir "${modbus_dir}" ABSOLUTE)
get_filename_component(modbus_component "${modbus_dir}" NAME)

idf_component_register(SRCS "test_serial_master_teardown.c"
                       PRIV_INCLUDE_DIRS "${modbus_dir}/modbus/mb_controller/common"
                                         "${modbus_dir}/modbus/mb_objects/include"
                       PRIV_REQUIRES ${modbus_component} unity)

idf_component_get_property(modbus_lib ${modbus_component} COMPONENT_LIB)
get_target_property(modbus_definitions ${modbus_lib} COMPILE_DEFINITIONS)
if("MB_HAVE_ESP_TIMER_STOP_BLOCKING=1" IN_LIST modbus_definitions)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE MB_HAVE_ESP_TIMER_STOP_BLOCKING)
endif()

target_link_libraries(${COMPONENT_LIB} INTERFACE
                      "-Wl,--wrap=uart_driver_install"
                      "-Wl,--wrap=uart_get_buffered_data_len")
