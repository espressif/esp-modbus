*** Settings ***
Documentation     A test suite for Bug Bounty Program to verify observed issues.
...               Implements the Modbus Master (Client) to send requests
...               for Modbus Slave side (the DUT) and verifies the answers.
Resource          ModbusTestSuiteMaster.resource
Default Tags      multi_dut_modbus_generic
Suite Setup       Create Connection    ${MODBUS_DEF_IP}    ${MODBUS_DEF_PORT}
Suite Teardown    Disconnect

*** Variables ***
${suiteConnection}    None

*** Test Cases ***
Test Raw Frame Request
    [Documentation]    Send custom frame for different requests, and verify response
    [Template]     Raw Frame
    0x0000    0x06    0x01    [0x01, 0x00, 0x00, 0x00, 0x0A]    0    [0x01, 0x02, 0x55, 0x02]
    0x0000    0x06    0x01    [0x01, 0x00, 0x00, 0x01, 0x0A]    2    []
    0x0000    0x06    0x01    [0x02, 0x00, 0x00, 0x00, 0x0A]    0    [0x02, 0x02, 0x55, 0x00]
    0x0000    0x06    0x01    [0x02, 0x00, 0x00, 0x01, 0x0A]    2    []
    0x0000    0x06    0x01    [0x03, 0x00, 0x00, 0x00, 0x02]    0    [0x03, 0x04, 0x00, 0x55, 0x00, 0x55]
    # BBP#571: verify protocol field parsing bug causing a request semantic mismatch and validation bypass
    0x0000    0x06    0x01    [0x03, 0x00, 0x00, 0x01, 0x01]    3    []


Test Malformed MBAP Frame Should Disconnect
    [Documentation]    BBP#572 regression check: send various malformed MBAP
    ...    frames (non zero Protocol ID, over sized declared length, a frame
    ...    with a UID but no function code at all, and an out of range UID)
    ...    and verify the slave immediately drops the offending connection
    ...    and frees its slot for a new client, instead of leaving the
    ...    connection open (DoS / connection pool exhaustion).
    [Template]    Malformed Frame Should Disconnect
    # protoId    length    uid    customData                       validate
    1            6         1      [0x03, 0x00, 0x00, 0x00, 0x01]    ${False}
    0            250       1      [0x03, 0x00, 0x00, 0x00, 0x01]    ${True}
    0            1         1      []                                ${True}
    0            2         250    [0x03]                            ${True}
