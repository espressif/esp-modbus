*** Settings ***
Documentation     A test suite for Modbus Master testing.
...               This suite tests the Modbus slave implementation by waiting for
...               requests from the master and sending appropriate responses.
...               Keywords are imported from the resource file
Resource          ModbusTestSuiteSlave.resource
Default Tags      modbus_slave
Suite Setup       Set Log Level    DEBUG
# Suite Teardown    Test Start Verify Asynchronous    ${20}
Suite Teardown    Test Async Complete Modbus Cases    ${30}

*** Variables ***
${BINARY_REGS_AA}    "[0xAAAA, 0xAAAA,
...    0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA,
...    0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA,
...    0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA,
...    0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA,
...    0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA,
...    0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA,
...    0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA]"

${BINARY_REGS_00}    "[0x0000, 0x0000,
...    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
...    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
...    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
...    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
...    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
...    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
...    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000]"

*** Variables ***
${SKIP}           robot:skip

*** Test Cases ***

# Custom command send and report
# Test Register Transaction
Test Modbus Custom Command
    [Documentation]    Test custom command
    [Template]    Test Async Run Modbus Case
    [Tags]    Modbus Custom command
    # Unit ID, Function Code, Unused, Unused, Exception, Custom Data, Expected Response
    ""    0x01    0x41    0x0000    0    0    [0x4d, 0x61, 0x73, 0x74, 0x65, 0x72]    [0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x3A, 0x53, 0x6C, 0x61, 0x76, 0x65]

# The TCP master example does not implement this request for now, keep for future test
# Test Modbus Report Slave ID
#     [Documentation]    Test reporting slave ID
#     [Template]    Test Async Run Modbus Case
#     [Tags]    ${SKIP}
#     # Unit ID, Function Code, Expected Response
#     ""    0x01    0x11    0x0000    1    0    ${None}    [0x11, 0x05, 0x01, 0x0f, 0x33, 0x22, 0x11]

# Read Input Registers observed offsets/quantities
Test Modbus Read Input Registers
    [Documentation]    Test reading input registers with different addresses and quantities
    [Template]    Test Async Run Modbus Case
    "Data_channel_0"    0x01    0x04    0x0000    2    0    ${None}    [0x5c29, 0x3f8f]
    "Temperature_1"    0x01    0x04    0x0002    2    0    ${None}    [0xc28f, 0x4015]
    "Temperature_2"    0x01    0x04    0x0004    2    0    ${None}    [0xd70a, 0x4063]
#   ""    0x01    0x04    0x0004    2 [0xd70a, 0x4063] 04 04 d7 0a 40 63

Test Modbus Read Holding Registers
    [Documentation]    Test reading holding registers with different addresses and quantities
    [Template]    Test Async Run Modbus Case
    # Name, Unit ID, Function Code, Start Address, Quantity, Exception, Data, Expected Response
    # "Param1"    0x01    0x03    0x0000    2    0    ${None}    [0x0055, 0x0055]
    # "Param2"    0x01    0x03    0x0001    2    0    ${None}    [0x0055, 0x5500]
    # ""    0x01    0x03    0x0002    2    0    ${None}    [0xc28f, 0x4015]
    # ""    0x01    0x03    0x0004    2    0    ${None}    [0x3039, 0x3039]
    # ""    0x01    0x03    0x0006    2    0    ${None}    [0x3930, 0x3930]
    # ""    0x01    0x03    0x0008    4    0    ${None}    [0x3039, 0x0000, 0x3039, 0x0000]
    # ""    0x01    0x03    0x000c    4    0    ${None}    [0x0000, 0x3039, 0x0000, 0x3039]
    # ""    0x01    0x03    0x0010    4    0    ${None}    [0x3930, 0x0000, 0x3930, 0x0000]
    # ""    0x01    0x03    0x0014    4    0    ${None}    [0x0000, 0x3039, 0x0000, 0x3039]
    # ""    0x01    0x03    0x0018    4    0    ${None}    [0xe400, 0x4640, 0xe400, 0x4640]
    # ""    0x01    0x03    0x001c    4    0    ${None}    [0x4640, 0xe400, 0x4640, 0xe400]
    # ""    0x01    0x03    0x0020    4    0    ${None}    [0x00e4, 0x4046, 0x00e4, 0x4046]
    # ""    0x01    0x03    0x0024    4    0    ${None}    [0x4046, 0x00e4, 0x4046, 0x00e4]
    # ""    0x01    0x03    0x0028    8    0    ${None}    [0x0000, 0x0000, 0x1c80, 0x40c8, 0x0000, 0x0000, 0x1c80, 0x40c8]
    # ""    0x01    0x03    0x0030    8    0    ${None}    [0xc840, 0x801c, 0x0000, 0x0000, 0xc840, 0x801c, 0x0000, 0x0000]
    # ""    0x01    0x03    0x0038    8    0    ${None}    [0x40c8, 0x1c80, 0x0000, 0x0000, 0x40c8, 0x1c80, 0x0000, 0x0000]
    # ""    0x01    0x03    0x0040    8    0    ${None}    [0x0000, 0x0000, 0x801c, 0xc840, 0x0000, 0x0000, 0x801c, 0xc840]
    "Humidity_1"    0x02    0x03    0x004a    2    0    ${None}    [0x0000, 0x0000]
    "Humidity_2"    0x01    0x03    0x004c    2    0    ${None}    [0x0000, 0x0000]
    "Humidity_3"    0x01    0x03    0x004e    2    0    ${None}    [0x0000, 0x0000]
    "CustomHoldReg"    0x01    0x03    0x00f0    1    0    ${None}    [0x0000]
    "Test_regs"    0x01    0x03    0x0052    58    0    ${None}    ${BINARY_REGS_00}
    # ""    0x01    0x03    0x1234    1    0    ${None}    [0x0000]

Test Modbus Write Multiple Registers
    [Documentation]    Test writing multiple holding registers
    [Template]    Test Async Run Modbus Case
    # Name, Unit ID, Function Code, Start Address, Quantity, Byte Count, Register Values, Expected Response
    #""    0x01    0x10    0x0000    2    0    [0x1122,0x3344]    [0x0000, 0x0002]
    ""    0x01    0x10    0x0052    58    0    ${BINARY_REGS_AA}   [0x0052, 0x003A]

Test Modbus Read Coils
    [Documentation]    Test reading coils with different addresses and quantities
    [Template]    Test Async Run Modbus Case
    # Name, Unit ID, Function Code, Start Address, Quantity, Exception, Data, Expected Response
#    ""    0x01    0x01    0x0002    6    0    ${None}    [0x15]
    "RelayP1"    0x01    0x01    0x0002    6    0    ${None}    [0x2A]
#    "RelayP2"    0x01    0x01    0x000A    6    0    ${None}    [0x15]

# Test Modbus Write Single Coil
#     [Documentation]    Test writing a single coil
#     [Template]    Test Async Run Modbus Case
#     ""    0x01    0x05    0x0000    1    0    [0xFF00]    [0x00, 0x01]

# # Write Multiple Coils
# Test Modbus Write Multiple Coils
#     [Documentation]    Test writing multiple coils
#     [Template]    Test Async Run Modbus Case
#     # Name, Unit ID, Function Code, Start Address, Quantity, Byte Count, Output Values, Expected Response
#     ""    0x01    0x0F    0x0000    1    1    [0xFF]    [0x0000,0x0001]

# Test Modbus Read Discrete Inputs
#     [Documentation]    Test reading discrete inputs with different addresses and quantities
#     [Template]    Test Async Run Modbus Case
#     # Name, Unit ID, Function Code, Start Address, Quantity, Exception, Data, Expected Response
#     ""    0x01    0x02    0x0002    7    0    ${None}    [0x55]
