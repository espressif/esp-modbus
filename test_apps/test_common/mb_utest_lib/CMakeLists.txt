message(STATUS "mb_ut_lib: ${CMAKE_CURRENT_LIST_DIR}, ${CONFIG_MB_UTEST}")

add_library(mb_ut_lib "${CMAKE_CURRENT_LIST_DIR}/port_adapter.c"
                        "${CMAKE_CURRENT_LIST_DIR}/port_stubs.c")

idf_component_get_property(dir esp-modbus COMPONENT_DIR)
target_include_directories(mb_ut_lib PUBLIC 
                            "${CMAKE_CURRENT_LIST_DIR}"
                            "${CMAKE_CURRENT_LIST_DIR}/include"
                            "${dir}/modbus/mb_controller/common"
                            "${dir}/modbus/mb_controller/common/include"
                            "${dir}/modbus/mb_controller/serial"
                            "${dir}/modbus/mb_controller/tcp"
                            "${dir}/modbus/mb_objects/common"
                            "${dir}/modbus/mb_objects/include"
                            "${dir}/modbus/mb_ports/common"
                            "${dir}/modbus/mb_ports/serial"
                            "${dir}/modbus/mb_ports/tcp"
                            "${dir}/modbus/mb_transports"
                            "${dir}/modbus/mb_transports/rtu"
                            "${dir}/modbus/mb_transports/ascii"
                            "${dir}/modbus/mb_transports/tcp"
                            )

idf_component_get_property(driver_lib driver COMPONENT_LIB)
target_link_libraries(mb_ut_lib PUBLIC ${driver_lib})
idf_component_get_property(timer_lib esp_timer COMPONENT_LIB)
target_link_libraries(mb_ut_lib PUBLIC ${timer_lib})
idf_component_get_property(netif_lib esp_netif COMPONENT_LIB)
target_link_libraries(mb_ut_lib PUBLIC ${netif_lib})
idf_component_get_property(test_utils_lib test_utils COMPONENT_LIB)
target_link_libraries(mb_ut_lib PUBLIC ${test_utils_lib})


# Wrap port functions to substitute port with port_adapter object
if(CONFIG_MB_PORT_ADAPTER_EN)

    set(WRAP_FUNCTIONS
        mbm_port_tcp_create
        mbm_port_tcp_set_conn_cb
        mbm_port_tcp_get_slave_info
        mbm_port_tcp_send_data
        mbm_port_tcp_recv_data
        mbm_port_tcp_enable
        mbm_port_tcp_disable
        mbm_port_tcp_delete
        mbs_port_tcp_create
        mbs_port_tcp_enable
        mbs_port_tcp_disable
        mbs_port_tcp_send_data
        mbs_port_tcp_recv_data
        mbs_port_tcp_delete
        mb_port_event_post
        mb_port_event_get
        mb_port_ser_create
        mb_port_ser_recv_data
        mb_port_ser_send_data
        mb_port_ser_enable
        mb_port_ser_disable
        mb_port_ser_delete
    )

foreach(wrap ${WRAP_FUNCTIONS})
    target_link_libraries(mb_ut_lib PUBLIC "-Wl,--undefined=${wrap}")
    target_link_libraries(mb_ut_lib PUBLIC "-Wl,--wrap=${wrap}")
    #target_link_libraries(mb_ut_lib INTERFACE "-u __wrap_${wrap}")
endforeach()

endif()

# allow multiple symbol definitions
target_link_libraries(mb_ut_lib PUBLIC "-Wl,--allow-multiple-definition")

if(CONFIG_MB_PORT_ADAPTER_EN)
    set_property(TARGET ${COMPONENT_LIB} APPEND PROPERTY INTERFACE_LINK_LIBRARIES "-u mb_test_include_stub_impl")
endif()