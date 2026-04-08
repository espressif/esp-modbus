set(PROJECT_NAME "mb_serial_cpp")

idf_component_register(SRCS "serial_test.cpp"
                    REQUIRES esp-modbus esp_common nvs_flash esp_event esp_timer lwip
                    INCLUDE_DIRS ".")

# Explicitly use C++17 so we can get std::atomic support for the workaround in mb_port_types.h
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)

# Workaround to avoid static analysis false positives for some components.
if(CONFIG_FMB_COMPILER_STATIC_ANALYZER_ENABLE AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${COMPONENT_LIB} PRIVATE "-fanalyzer")
    message(STATUS "Static analyzer build for ${PROJECT_NAME}.")
endif()
