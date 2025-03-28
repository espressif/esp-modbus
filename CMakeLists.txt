# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
set(srcs
    "mb_controller/common/esp_modbus_common.c"
    "mb_controller/common/esp_modbus_master.c"
    "mb_controller/common/esp_modbus_slave.c"
    "mb_controller/common/esp_modbus_master_serial.c"
    "mb_controller/common/esp_modbus_slave_serial.c"
    "mb_controller/common/esp_modbus_master_tcp.c"
    "mb_controller/common/esp_modbus_slave_tcp.c"
    "mb_controller/serial/mbc_serial_master.c"
    "mb_controller/serial/mbc_serial_slave.c"
    "mb_controller/tcp/mbc_tcp_master.c"
    "mb_controller/tcp/mbc_tcp_slave.c"
    "mb_objects/mb_master.c"
    "mb_objects/mb_slave.c"
    "mb_objects/functions/mbfunc_handling.c"
    "mb_objects/functions/mbfunccoils_master.c"
    "mb_objects/functions/mbfunccoils.c"
    "mb_objects/functions/mbfuncdiag.c"
    "mb_objects/functions/mbfuncdisc_master.c"
    "mb_objects/functions/mbfuncdisc.c"
    "mb_objects/functions/mbfuncholding_master.c"
    "mb_objects/functions/mbfuncholding.c"
    "mb_objects/functions/mbfuncinput_master.c"
    "mb_objects/functions/mbfuncinput.c"
    "mb_objects/functions/mbfuncother.c"
    "mb_objects/functions/mbutils.c"
    "mb_ports/common/port_event.c"
    "mb_ports/common/port_other.c"
    "mb_ports/common/port_timer.c"
    "mb_ports/common/mb_transaction.c"
    "mb_ports/serial/port_serial.c"
    "mb_ports/tcp/port_tcp_master.c"
    "mb_ports/tcp/port_tcp_slave.c"
    "mb_ports/tcp/port_tcp_driver.c"
    "mb_ports/tcp/port_tcp_utils.c"
    "mb_transports/rtu/rtu_master.c"
    "mb_transports/rtu/rtu_slave.c"
    "mb_transports/rtu/mbcrc.c"
    "mb_transports/ascii/ascii_master.c"
    "mb_transports/ascii/ascii_slave.c"
    "mb_transports/ascii/ascii_lrc.c"
    "mb_transports/tcp/tcp_master.c"
    "mb_transports/tcp/tcp_slave.c"
)

set(include_dirs mb_transports mb_controller/common/include mb_objects/common mb_ports/common mb_ports/serial mb_ports/tcp)

set(priv_include_dirs mb_controller/serial mb_controller/tcp mb_controller/common mb_objects/include mb_transports/rtu mb_transports/ascii mb_transports/tcp)

if(CONFIG_FMB_EXT_TYPE_SUPPORT)
     list(APPEND srcs "mb_controller/common/mb_endianness_utils.c")
endif()

add_prefix(srcs "${CMAKE_CURRENT_LIST_DIR}/modbus/" ${srcs})
add_prefix(include_dirs "${CMAKE_CURRENT_LIST_DIR}/modbus/" ${include_dirs})
add_prefix(priv_include_dirs "${CMAKE_CURRENT_LIST_DIR}/modbus/" ${priv_include_dirs})

message(STATUS "DEBUG: Use esp-modbus component folder: ${CMAKE_CURRENT_LIST_DIR}.")

set(requires driver)
set(priv_requires esp_netif esp_event vfs)

# esp_timer component was introduced in v4.2
if("${IDF_VERSION_MAJOR}.${IDF_VERSION_MINOR}" VERSION_GREATER "4.1")
    list(APPEND requires esp_timer)
endif()

idf_component_register(SRCS "${srcs}"
                        INCLUDE_DIRS "${include_dirs}"
                        PRIV_INCLUDE_DIRS "${priv_include_dirs}"
                        REQUIRES ${requires} 
                        PRIV_REQUIRES ${priv_requires}
                        LDFRAGMENTS linker.lf)

# This is an alternative of macro `idf_component_optional_requires(PUBLIC mdns)` to support all versions of esp-idf 
set(optional_reqs mdns espressif__mdns)
idf_build_get_property(build_components BUILD_COMPONENTS)
message(STATUS "build_components = ${build_components}")
foreach(req ${optional_reqs} ${exclude_comps})
    if(req IN_LIST build_components)
        idf_component_get_property(req_lib ${req} COMPONENT_LIB)
        target_link_libraries(${COMPONENT_LIB} PRIVATE ${req_lib})
        message(STATUS "Req ${req} is found and added into ${COMPONENT_NAME} dependencies.")
        target_compile_definitions(${COMPONENT_LIB} PUBLIC -DMB_MDNS_IS_INCLUDED)
    endif()
endforeach()

# target_link_options(${COMPONENT_LIB} INTERFACE -fsanitize=undefined -fsanitize=alignment) #-fsanitize=address -fsanitize=undefined
# target_link_options(${COMPONENT_LIB} INTERFACE -fsanitize=address)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-strict-aliasing -Wno-write-strings -Werror)

message(STATUS "The mdns included is: ${MB_MDNS_IS_INCLUDED}")
