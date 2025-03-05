*** Variables ***
${MODBUS_DEF_SERVER_IP}    127.0.0.1
${MODBUS_DEF_PORT}         1502
${PAR1}     1
${PAR2}     2

${FUNC_REPORT_SLAVE_ID}             ${0x11}
${FUNC_WRITE_HOLDING_REGISTERS}     ${0x10}
${FUNC_WRITE_HOLDING_REGISTER}      ${0x06}
${FUNC_READ_HOLDING_REGISTERS}      ${0x03}
${FUNC_READ_INPUT_REGISTERS}        ${0x04}
${FUNC_READ_COILS}                  ${0x01}
${FUNC_WRITE_COILS}                 ${0x0F}
${FUNC_READ_DISCRETE_INPUTS}        ${0x02}

*** Settings ***
Library    Collections
Library    ModbusTestLib.py    WITH NAME    ModbusTestLib

*** Keywords ***
Create Custom Command Request
    [Arguments]    ${uid}    ${customData}
    ${packet} =    Create Request    ModbusADU_Request(unitId=${uid}, protoId=0)/ModbusPDUXX_Custom_Request(customBytes=${customData})
    RETURN    ${packet}

Create Report Slave Id Request
    [Arguments]    ${uid}    ${customData}
    #${packet} =    Create Request    ModbusADU_Request(unitId=${uid}, protoId=0)/ModbusPDU11_Report_Slave_Id(funcCode=${FUNC_REPORT_SLAVE_ID})
    ${packet} =    Create Request    ModbusADU_Request(unitId=${uid}, protoId=0)/ModbusPDUXX_Custom_Request(customBytes=${customData})
    RETURN    ${packet}

Create Input Read Registers Request
    [Arguments]    ${uid}    ${startAddr}    ${quantity}
    ${packet} =    Create Request    ModbusADU_Request(unitId=${uid}, protoId=0, len=6)/ModbusPDU04_Read_Input_Registers(funcCode=${FUNC_READ_INPUT_REGISTERS}, startAddr=${startAddr}, quantity=${quantity})
    RETURN    ${packet}

Create Holding Read Registers Request
    [Arguments]    ${uid}    ${startAddr}    ${quantity}
    ${packet} =    Create Request    ModbusADU_Request(unitId=${uid}, protoId=0, len=6)/ModbusPDU03_Read_Holding_Registers(funcCode=${FUNC_READ_HOLDING_REGISTERS}, startAddr=${startAddr}, quantity=${quantity})
    RETURN    ${packet}

Create Holding Write Registers Request
    [Arguments]    ${uid}    ${startAddr}    ${quantity}    ${data}
    ${packet} =    Create Request    ModbusADU_Request(unitId=${uid}, protoId=0)/ModbusPDU10_Write_Multiple_Registers(funcCode=${FUNC_WRITE_HOLDING_REGISTERS}, startAddr=${startAddr}, quantityRegisters=${quantity}, outputsValue=${data})
    Log    Packet: ${packet}
    RETURN    ${packet}

Create Holding Write Register Request
    [Arguments]    ${uid}    ${startAddr}    ${data}
    ${packet} =    Create Request    ModbusADU_Request(unitId=${uid}, protoId=0)/ModbusPDU06_Write_Single_Register(funcCode=${FUNC_WRITE_HOLDING_REGISTER}, registerAddr=${startAddr}, registerValue=${data})
    Log    Packet: ${packet}
    RETURN    ${packet}

Create Coils Read Request
    [Arguments]    ${uid}    ${startAddr}    ${quantity}
    ${packet} =    Create Request    ModbusADU_Request(unitId=${uid}, protoId=0)/ModbusPDU01_Read_Coils(funcCode=${FUNC_READ_COILS}, startAddr=${startAddr}, quantity=${quantity})
    Log    Packet: ${packet}
    RETURN    ${packet}

Create Coils Write Request
    [Arguments]    ${uid}    ${startAddr}    ${quantity}    ${coil_data}
    ${packet} =    Create Request    ModbusADU_Request(unitId=${uid}, protoId=0)/ModbusPDU0F_Write_Multiple_Coils(funcCode=${FUNC_WRITE_COILS}, startAddr=${startAddr}, quantityOutput=${quantity}, outputsValue=${coil_data})
    Log    Packet: ${packet}
    RETURN    ${packet}

Create Discrete Read Request
    [Arguments]    ${uid}    ${startAddr}    ${quantity}
    ${packet} =    Create Request    ModbusADU_Request(unitId=${uid}, protoId=0)/ModbusPDU02_Read_Discrete_Inputs(funcCode=${FUNC_READ_DISCRETE_INPUTS}, startAddr=${startAddr}, quantity=${quantity})
    Log    Packet: ${packet}
    RETURN    ${packet}

Lists Should Be Equal
    [Arguments]    ${get_list}    ${exp_list}
    Should Not Be Empty    ${get_list}
    Should Not Be Empty    ${exp_list}
    ${get_length} =    Get length    ${get_list}
    ${exp_length} =    Get length    ${exp_list}
    Should Be Equal As Integers    ${get_length}    ${exp_length}
    FOR    ${i}    IN RANGE    ${exp_length}
        ${get_item} =    Get From List    ${get_list}    ${i}
        ${exp_item} =    Get From List    ${exp_list}    ${i}
        Should Be Equal As Integers    ${get_item}    ${exp_item}
    END

Custom Command
    [Arguments]    ${uid}    ${customData}    ${exception_expected}    ${expected_list}
    ${classId} =    Get Class Id
    Log    Library ClassId: ${classId}
    Log    Get Slave Identificator UID:${uid}, Custom bytes: ${customData}
    ${req} =    Create Custom Command Request    ${uid}    ${customData}
    #Create Connection    ${server}    ${port}
    ${response_frame} =    Send Packet And Get Response    ${req}
    Should Not Be Empty    ${response_frame}
    ${packet} =    Translate Response    ${response_frame}
    Should Be Equal As Integers    ${req.transId}    ${packet.transId}
    ${exception}    ${exp_message} =    Check Response    ${packet}    ${req.customBytes[0]}
    Should Be Equal As Integers    ${exception}    ${exception_expected}
    Log    exception: (${exception}: ${exp_message}), expected: ${exception_expected}
    IF    ${exception} == ${0}
        Log    SlaveUID:${uid}, Custom_data received:${packet.customBytes}
        IF    ${expected_list} != ${None}
            Log    ${expected_list}
            Log    ${packet.customBytes}
            ${get_list} =    Convert To List    ${packet.customBytes}
            ${exp_list} =    Evaluate    ${expected_list}
            Lists Should Be Equal    ${get_list}    ${exp_list}
        ELSE
            Log    "Skip comparison with expected list"
        END
    ELSE
        Log    "Exception is evaluated correctly (${exception}: ${exp_message}) == ${exception_expected}"
    END

Report Slave Id
    [Arguments]    ${uid}    ${customData}   ${exception_expected}
    ${classId} =    Get Class Id
    Log    Library ClassId: ${classId}
    Log    Get Slave Identificator UID:${uid}, Custom bytes: ${customData}
    ${req} =    Create Report Slave Id Request    ${uid}    ${customData}
    #Create Connection    ${server}    ${port}
    ${response_frame} =    Send Packet And Get Response    ${req}
    Should Not Be Empty    ${response_frame}
    ${packet} =    Translate Response    ${response_frame}
    Should Be Equal As Integers    ${req.transId}    ${packet.transId}
    #${exception}    ${exp_message} =    Check Response    ${packet}    ${req.funcCode}
    ${exception}    ${exp_message} =    Check Response    ${packet}    ${req.customBytes[0]}
    Should Be Equal As Integers    ${exception}    ${exception_expected}
    Log    exception: (${exception}: ${exp_message}), expected: ${exception_expected}
    IF    ${exception} == ${0}
        Log    Bytes count is: ${packet.byteCount}
        Log    SlaveUID:${packet.slaveUid}, runIdicatorStatus:${packet.runIdicatorStatus}, Identificator:${packet.slaveIdent}
    ELSE
        Log    "Exception is evaluated correctly (${exception}: ${exp_message}) == ${exception_expected}"
    END

Read Input Registers
    [Arguments]    ${uid}    ${start_addr}    ${quantity}    ${exception_expected}
    ${classId} =    Get Class Id
    Log    Library ClassId: ${classId}
    Log    Read Input Registers with parameters UID:${uid}, offs:${start_addr}, quantity:${quantity}
    ${req} =    Create Input Read Registers Request    ${uid}    ${start_addr}    ${quantity}
    #Create Connection    ${server}    ${port}
    ${response_frame} =    Send Packet And Get Response    ${req}
    Should Not Be Empty    ${response_frame}
    ${packet} =    Translate Response    ${response_frame}
    Should Be Equal As Integers    ${req.transId}    ${packet.transId}
    ${exception}    ${exp_message} =    Check Response    ${packet}    ${req.funcCode}
    Should Be Equal As Integers    ${exception}    ${exception_expected}
    Log    exception: (${exception}: ${exp_message}), expected: ${exception_expected}
    IF    ${exception} == ${0}
        ${vallist} =    Convert To List    ${packet.registerVal}
        Should Not Be Empty    ${vallist}
        Log     Modbus register values:${vallist}
        FOR    ${item}    IN    @{vallist}
            Log     Modbus register value:${item}
            #Append To List    ${}    ${item}
        END
        ${length} =    Get length    ${vallist}
        Log    Items count is: ${length}
        Should Be Equal As Integers    ${length}    ${quantity}
    ELSE
        Log    "Exception is evaluated correctly (${exception}: ${exp_message}) == ${exception_expected}"
    END

Read Holding Registers
    [Arguments]    ${uid}    ${start_addr}    ${quantity}    ${exception_expected}
    ${classId} =    Get Class Id
    Log    Library ClassId: ${classId}
    Log    Read Holding Registers with parameters UID:${uid}, offs:${start_addr}, quantity:${quantity}
    ${req} =    Create Holding Read Registers Request    ${uid}    ${start_addr}    ${quantity}
    #Create Connection    ${server}    ${port}
    ${response_frame} =    Send Packet And Get Response    ${req}
    Should Not Be Empty    ${response_frame}
    ${packet} =    Translate Response    ${response_frame}
    Should Be Equal As Integers    ${req.transId}    ${packet.transId}
    ${exception}    ${exp_message} =    Check Response    ${packet}    ${req.funcCode}
    Log    exception: (${exception}: ${exp_message}), expected: ${exception_expected}
    Should Be Equal As Integers    ${exception}    ${exception_expected}
    IF    ${exception} == ${0}
        ${vallist} =    Convert To List    ${packet.registerVal}
        Should Not Be Empty    ${vallist}
        Log     Modbus register values:${vallist}
        FOR    ${item}    IN    @{vallist}
            Log     Modbus register value:${item}
            #Append To List    ${}    ${item}
        END
        ${length} =    Get length    ${vallist}
        Log    Items count is: ${length}
        Should Be Equal As Integers    ${length}    ${quantity}
    ELSE
        Log    "Exception is evaluated correctly ${exception} == ${exception_expected}"
    END

Write Holding Registers
    [Arguments]    ${uid}    ${start_addr}    ${quantity}    ${data}    ${exception_expected}
    ${classId} =    Get Class Id
    Log    Library ClassId: ${classId}
    Log    Write Hold Registers with parameters UID:${uid}, offs:${start_addr}, quantity:${quantity}, data:${data}
    ${req} =    Create Holding Write Registers Request    ${uid}    ${start_addr}    ${quantity}    ${data}
    #Create Connection    ${server}    ${port}
    ${response_frame} =    Send Packet And Get Response    ${req}
    Should Not Be Empty    ${response_frame}
    ${packet} =    Translate Response    ${response_frame}
    Should Be Equal As Integers    ${req.transId}    ${packet.transId}
    Should Not Be Empty    ${packet}
    Log      Response is: ${packet.show(dump=True)}
    ${exception}    ${exp_message} =    Check Response    ${packet}    ${req.funcCode}
    Log    exception: (${exception}: ${exp_message}), expected: ${exception_expected}
    Should Be Equal As Integers    ${exception}    ${exception_expected}
    Run Keyword If      ${exception} == ${0}    Should Be Equal As Integers    ${${packet.quantityRegisters}}    ${quantity}
    ...                 ELSE    Log    "Exception is evaluated correctly ${exception} == ${exception_expected}"

Write Single Holding Register
    [Arguments]    ${uid}    ${start_addr}    ${data}    ${exception_expected}
    ${classId} =    Get Class Id
    Log    Library ClassId: ${classId}
    Log    Write Single Holding Register with parameters UID:${uid}, offs:${start_addr}
    ${req} =    Create Holding Write Register Request    ${uid}    ${start_addr}    ${data}
    #Create Connection    ${server}    ${port}
    ${response_frame} =    Send Packet And Get Response    ${req}
    Should Not Be Empty    ${response_frame}
    ${packet} =    Translate Response    ${response_frame}
    Should Not Be Empty    ${packet}
    Log      Response is: ${packet.show(dump=True)}
    Should Be Equal As Integers    ${req.transId}    ${packet.transId}
    ${exception}    ${exp_message} =    Check Response    ${packet}    ${req.funcCode}
    Log    exception: (${exception}: ${exp_message}), expected: ${exception_expected}
    Should Be Equal As Integers    ${exception}    ${exception_expected}
    Run Keyword If      ${exception} == ${0}    Should Be Equal As Integers    ${${packet.registerValue}}    ${data}
    ...                 ELSE    Log    "Exception is evaluated correctly ${exception} == ${exception_expected}"

Read Coil Registers
    [Arguments]    ${uid}    ${start_addr}    ${quantity}    ${exception_expected}
    ${classId} =    Get Class Id
    Log    Library ClassId: ${classId}
    Log    Read Coil Registers with parameters UID:${uid}, offs:${start_addr}, quantity:${quantity}
    ${req} =    Create Coils Read Request    ${uid}    ${start_addr}    ${quantity}
    ${response_frame} =    Send Packet And Get Response    ${req}
    Should Not Be Empty    ${response_frame}
    ${packet} =    Translate Response    ${response_frame}
    Should Not Be Empty    ${packet}
    Log      Response is: ${packet.show(dump=True)}
    Should Be Equal As Integers    ${req.transId}    ${packet.transId}
    ${exception}    ${exp_message} =    Check Response    ${packet}    ${req.funcCode}
    Log    exception: (${exception}: ${exp_message}), expected: ${exception_expected}
    Should Be Equal As Integers    ${exception}    ${exception_expected}
    IF    ${exception} == ${0}
        ${coils} =    Get Bits From PDU    ${packet}
        Should Not Be Empty    ${coils}
        Should Be Equal As Integers    ${${coils.__len__()}}    ${${packet.byteCount} * 8}
        Log    Returned modbus coils: ${coils}
    ELSE
        Log    "Exception is evaluated correctly ${exception} == ${exception_expected}"
    END

Write Coil Registers
    [Arguments]    ${uid}    ${start_addr}    ${quantity}    ${coil_data}    ${exception_expected}
    ${classId} =    Get Class Id
    Log    Library ClassId: ${classId}
    Log    Write Coil Registers with parameters UID:${uid}, offs:${start_addr}, quantity:${quantity}, coil_data:${coil_data}
    ${req} =    Create Coils Write Request    ${uid}    ${start_addr}    ${quantity}    ${coil_data}
    ${response_frame} =    Send Packet And Get Response    ${req}
    Should Not Be Empty    ${response_frame}
    ${packet} =    Translate Response    ${response_frame}
    Should Not Be Empty    ${packet}
    Log      Response is: ${packet.show(dump=True)}
    Should Be Equal As Integers    ${req.transId}    ${packet.transId}
    ${exception}    ${exp_message} =    Check Response    ${packet}    ${req.funcCode}
    Log    exception: (${exception}: ${exp_message}), expected: ${exception_expected}
    Should Be Equal As Integers    ${exception}    ${exception_expected}
    IF    ${exception} == ${0}
        Log    ${${packet.quantityOutput}}
        Should Be Equal As Integers    ${${packet.quantityOutput}}    ${quantity}
    ELSE
        Log    "Exception is evaluated correctly ${exception} == ${exception_expected}"
    END

Read Discrete Input Registers
    [Arguments]    ${uid}    ${start_addr}    ${quantity}    ${exception_expected}
    ${classId} =    Get Class Id
    Log    Library ClassId: ${classId}
    Log    Read Discrete Input Registers with parameters UID:${uid}, offs:${start_addr}, quantity:${quantity}
    ${req} =    Create Discrete Read Request    ${uid}    ${start_addr}    ${quantity}
    ${response_frame} =    Send Packet And Get Response    ${req}
    Should Not Be Empty    ${response_frame}
    ${packet} =    Translate Response    ${response_frame}
    Should Not Be Empty    ${packet}
    Log      Response is: ${packet.show(dump=True)}
    Should Be Equal As Integers    ${req.transId}    ${packet.transId}
    ${exception}    ${exp_message} =    Check Response    ${packet}    ${req.funcCode}
    Log    exception: (${exception}: ${exp_message}), expected: ${exception_expected}
    Should Be Equal As Integers    ${exception}    ${exception_expected}
    IF    ${exception} == ${0}
        ${dicretes} =    Get Bits From PDU    ${packet}
        Should Not Be Empty    ${dicretes}
        Should Be Equal As Integers    ${${dicretes.__len__()}}    ${${packet.byteCount} * 8}
        Log    Returned modbus dicretes: ${dicretes}
    ELSE
        Log    "Exception is evaluated correctly ${exception} == ${exception_expected}"
    END

Send Packet And Get Response
    [Arguments]    ${packet}
    ${response} =    Send Packet    ${packet}    timeout=3    verbose=1
    Log    Got response ${response}
    RETURN    ${response}

Create Connection
    [Arguments]    ${host}    ${port}
    ${classId} =    Get Class Id
    Log    Library ClassId: ${classId}
    ${connection} =    Connect    ${host}    ${port}
    IF    ${connection}
        Log    Connection to host: ${host}:${port} established.
    ELSE
        Log    Connection to host: ${host}:${port} failed.
    END
    RETURN    ${connection}
