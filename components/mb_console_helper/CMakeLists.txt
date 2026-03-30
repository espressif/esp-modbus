idf_component_register(SRCS "mb_console.c"
                       INCLUDE_DIRS "include"
                       REQUIRES console
                       LDFRAGMENTS linker.lf)

if(CONFIG_MB_CONSOLE_CMD_AUTO_REGISTRATION)
    target_link_libraries(${COMPONENT_LIB} PRIVATE "-u mb_console_cmd_mb_register")
endif()
