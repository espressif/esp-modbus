*** Settings ***
Documentation     A test suite for Modbus Slave testing.
...               Implements the Modbus Master (Client) to send requests
...               for Modbus Slave side (the DUT) and verifies the answers.
...               Keywords are imported from the resource file
Resource          ModbusTestSuiteMaster.resource
Default Tags      multi_dut_modbus_generic
Suite Setup       Create Connection    ${MODBUS_DEF_IP}    ${MODBUS_DEF_PORT}
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

Test Write Single Holding Register
    [Documentation]    Test write one single holding register
    [Template]    Write Single Holding Register
    0x01    0x0001    0x1122    0
    0x01    0x0010    0x3344    0

Test Custom Command Request
    [Documentation]    Test reading slave UID, running status, identificator structure (use custom frame template)
    [Template]    Custom Command
    0x01    [0x41]    1    ${None}
