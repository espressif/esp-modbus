idf_component_register(
    SRCS "basic_master.c"
    INCLUDE_DIRS "."
    REQUIRES  nvs_flash esp_netif mdns esp_event esp_wifi driver esp_eth
)

# Workaround to avoid static analysis false positives for some components.
if(CONFIG_FMB_COMPILER_STATIC_ANALYZER_ENABLE AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${COMPONENT_LIB} PRIVATE "-fanalyzer")
    message(STATUS "Static analyzer build for ${PROJECT_NAME}.")
endif()
