set(priv_include_dirs)

if(CONFIG_MB_USE_TRANSPORT_FACTORY)
    # The factory example delegates to the stock RTU transport, whose constructor
    # and transitive headers are intentionally internal to the esp-modbus component.
    list(APPEND priv_include_dirs
         "../../../../modbus/mb_transports/rtu"
         "../../../../modbus/mb_transports"
         "../../../../modbus/mb_objects/include"
         "../../../../modbus/mb_objects/common"
         "../../../../modbus/mb_ports/common")
endif()

idf_component_register(SRCS "serial_slave.c"
                    INCLUDE_DIRS "."
                    PRIV_INCLUDE_DIRS "${priv_include_dirs}")

set(PROJECT_NAME "modbus_serial_slave")

# Workaround to avoid static analysis false positives for some components.
if(CONFIG_FMB_COMPILER_STATIC_ANALYZER_ENABLE AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${COMPONENT_LIB} PRIVATE "-fanalyzer")
    message(STATUS "Static analyzer build for ${PROJECT_NAME}.")
endif()
