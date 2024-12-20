*** Settings ***
Documentation     A test suite for Modbus commands.
...
...               Keywords are imported from the resource file
Resource          ModbusTestSuite.resource
Default Tags      multi_dut_modbus_generic
Suite Setup       Create Connection    ${MODBUS_DEF_SERVER_IP}    ${MODBUS_DEF_PORT}
Suite Teardown    Disconnect

*** Variables ***
${suiteConnection}    None

*** Test Cases ***
Test Read Holding Registers With Different Addresses And Quantities
    [Documentation]    Test reading holding registers from different addresses with different quantities
    [Template]    Read Holding Registers
    0x01    0x0001    2    0
    0x01    0x0002    3    0

Test Write Holding Registers With Different Addresses And Quantities
    [Documentation]    Test write holding registers for different addresses with different quantities
    [Template]    Write Holding Registers
    0x01    0x0003    2    [0x1122, 0x3344]             0
    0x01    0x0004    3    [0x1122, 0x3344, 0x5566]     0

Test Read Input Registers With Different Addresses And Quantities
    [Documentation]    Test read input registers for different addresses with different quantities
    [Template]    Read Input Registers
    0x01    0x0003    2         0
    0x01    0x0004    3         0
    0x01    0x0001    200       3
    0x01    0x2344    3         2

Test Write Single Holding Register
    [Documentation]    Test write one single holding register
    [Template]    Write Single Holding Register
    0x01    0x0001    0x1122    0
    0x01    0x2344    0x1122    2
    0x01    0x0010    0x3344    0

Test Read Coils With Different Addresses And Quantities
    [Documentation]    Test read coil registers for different addresses with different quantities
    [Template]    Read Coil Registers
    0x01    0x0001    0      3
    0x01    0x0001    16     0
    0x01    0x0010    20     2
    0x01    0x0002    300    2
    0x01    0x0008    30     2

Test Read Discrete Inputs With Different Addresses And Quantities
    [Documentation]    Test read discrete registers for different addresses with different quantities
    [Template]    Read Discrete Input Registers
    0x01    0x0001    0      3
    0x01    0x0001    16     0
    0x01    0x0010    20     2
    0x01    0x0002    300    2
    0x01    0x0008    30     2

Test Write Coils With Different Addresses And Quantities
    [Documentation]    Test write coil registers for different addresses with different quantities
    [Template]    Write Coil Registers
    0x01    0x0000    8      [0xFF]         0
    0x01    0x0005    300    [0xFF]         3
    0x01    0x0008    16     [0xFF, 0x55]   0