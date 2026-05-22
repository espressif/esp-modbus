*** Settings ***
Library    Collections
Library    ModbusSlaveLib.py    WITH NAME    ModbusSlaveLib
Library    AsyncLibrary

*** Variables ***

${MODBUS_SERVER_ADDRESS}    127.0.0.1
${MODBUS_DEF_IP}    127.0.0.1
${MODBUS_DEF_PORT}    ${1502}
${MODBUS_TIMEOUT}    ${30}
@{EXP_TRANSACTIONS}
@{REGISTERED_HANDLES}

*** Keywords ***
Test Ensure Server Started
    [Arguments]    ${port}=${MODBUS_DEF_PORT}    ${timeout}=${MODBUS_TIMEOUT}    ${async}=False
    [Documentation]    Start the Modbus server and begin capturing packets
    ${class_uid} =    ModbusSlaveLib.Get Class Id
    Log    "Try to start server: ${class_uid}:${port}"
    ${status} =    ModbusSlaveLib.Start Server    ${port}    ${timeout}    ${async}
    RETURN    ${status}

Test Stop Server
    [Documentation]    Stop the Modbus server and packet capture
    ModbusSlaveLib.Stop Server

Test Report Server Address
    [Arguments]    ${address}=${None}
    [Documentation]    Test wrapper to get active server address and port tuple (handled by listener)
    Log    "Server reported address: ${address}"
    Set Suite Variable    $MODBUS_SERVER_ADDRESS    ${address}    children=True

Test Register Transaction
    [Arguments]    ${uid}    ${func_code}    ${start_addr}=0    ${quantity}=1    ${exception}=0    ${data}=${None}    ${expected_response}=${None}
    [Documentation]    Register expected request and response
    ${class_uid} =    ModbusSlaveLib.Get Class Id
    Log    "Library class: ${class_uid}"
    ${exp_transaction} =    ModbusSlaveLib.Add Expected Transaction
    ...    ${{eval($uid)}}    ${{eval($func_code)}}    ${{eval($start_addr)}}    ${{eval($quantity)}}    ${{eval($exception)}}    ${{eval('${data}')}}    ${{eval('${expected_response}')}}
    Append To List    ${EXP_TRANSACTIONS}    ${exp_transaction}
    Log    "Transaction registered: ${exp_transaction}"
    RETURN    ${exp_transaction}

Test Register Transaction Wait Confirmation
    [Arguments]    ${uid}    ${func_code}    ${start_addr}=0    ${quantity}=1    ${exception}=0    ${data}=${None}    ${expected_response}=${None}    ${timeout}=${20}
    [Documentation]    Append expected request and response to the list then wait for transaction to be handled
    Test Ensure Server Started    ${MODBUS_DEF_PORT}    ${timeout}    ${True}
    ${transaction} =    Test Register Transaction    ${uid}    ${func_code}    ${start_addr}    ${quantity}    ${exception}     ${data}    ${expected_response}
    Log    "Transaction created: ${transaction}"
    ${result} =    ModbusSlaveLib.Wait Transaction Confirmation    transaction=${transaction}    timeout=${timeout}
    # Should Not Be Equal    ${result}    ${None}
    Run Keyword If    ${result} == ${None}    Fail    "No confirmation received for transaction: ${transaction.request.summary()}, ${transaction.response.summary()}"
    RETURN    ${result}

Test Async Run Modbus Case
    [Arguments]    ${name}    ${uid}    ${func_code}    ${start_addr}=0    ${quantity}=1    ${exception}=0    ${data}=${None}    ${expected_response}=${None}    ${timeout}=${20}
    [Documentation]    Register expected transaction asynchronously (register+wait wrapper) and append handle
    # Log    "Parameters: ${uid} ${func_code} ${start_addr} ${quantity} ${exception} ${data} ${expected_response}"
    ${handle} =    Async Run    Test Register Transaction Wait Confirmation    ${uid}    ${func_code}    ${start_addr}    ${quantity}    ${exception}    ${data}    ${expected_response}    ${timeout}
    Append To List    ${REGISTERED_HANDLES}    ${handle}
    Log    "Handle for function: ${func_code}, ${handle}, List: ${REGISTERED_HANDLES}"
    # Register parameter name in test message attribute for tracing
    Run Keyword If    ${name} and ${${name.__len__()}}    Set Test Message    ${name}    append=yes
    RETURN    ${handle}

Test Async Run Modbus Case Register Only
    [Arguments]    ${name}    ${uid}    ${func_code}    ${start_addr}=0    ${quantity}=1    ${exception}=0    ${data}=${None}    ${expected_response}=${None}    ${timeout}=${2}
    [Documentation]    Register expected transaction asynchronously (register-only) and append async handle
    ${handle} =    Async Run    Test Register Transaction    ${uid}    ${func_code}    ${start_addr}    ${quantity}    ${exception}    ${data}    ${expected_response}
    Test Ensure Server Started    ${MODBUS_DEF_PORT}    ${timeout}    ${True}
    Append To List    ${REGISTERED_HANDLES}    ${handle}
    Log    "Register-only handle for function: ${func_code}, ${handle}, List: ${REGISTERED_HANDLES}"
    Run Keyword If    ${name} and ${${name.__len__()}}    Set Test Message    ${name}    append=yes
    RETURN    ${handle}

Test Async Complete Modbus Cases
    [Arguments]    ${timeout}=${2}
    [Documentation]    Wait for all previously registered async test-case handles to complete and verify confirmations
    # Allow small time for all async registration tasks to finish (acts like an "await" window)
    Test Ensure Server Started    ${MODBUS_DEF_PORT}    ${timeout}    ${True}
    ${address} =    Get Server Address
    Log    "Server reported address: ${address}"
    Test Report Server Address    ${address[0]}

    ${n_keywords} =    Get Length    ${REGISTERED_HANDLES}
    Log    "Completing ${n_keywords} async tasks: ${REGISTERED_HANDLES}"

    FOR    ${i}    IN RANGE    ${n_keywords}
        ${handle} =    Get From List    ${REGISTERED_HANDLES}    ${i}
        Log    "Completing transaction handle ${i} = ${handle}"
        ${return_value}    Async Get    ${handle}

        ${status} =    Set Variable    ${return_value}
        IF    "${return_value} is not ${None}"
            ${is_transaction} =      Evaluate     isinstance(${return_value}, ModbusSlaveLib.Transaction)
            IF    ${is_transaction}
                ${status} =    ModbusSlaveLib.Wait Transaction Confirmation    ${return_value}     ${timeout}
                Log    "Keyword ${i}, transaction: ${return_value}, confirmation: ${status}"
                Should Not Be Equal    ${status}    ${None}
            ELSE
                ${is_int} =      Evaluate     isinstance(${status}, int)
                IF    ${is_int}
                    Log    "Keyword ${i}, confirmed with TID: ${status}"
                END
            END
        ELSE
            Log    "Keyword ${i}, is not confirmed, result: ${status}"
            Fail    "Keyword ${i} is not confirmed."
        END
    END

    ModbusSlaveLib.Stop Server
    Log    "All async registered transactions completed."
    BuiltIn.Sleep    ${3}

    # Clear registered handles list for next run
    Set Test Variable    @{REGISTERED_HANDLES}    @{EMPTY}
    RETURN

Test Start Verify Synchronous
    [Arguments]    ${uid}    ${func_code}    ${start_addr}=0    ${quantity}=1    ${exception}=0    ${data}=${None}    ${expected_response}=${None}    ${timeout}=${2}
    [Documentation]    Test a Modbus request and response
    # Add the expected request and response
    ${class_uid} =    ModbusSlaveLib.Get Class Id
    Log    "Library class: ${class_uid}"
    Log    "Parameters: ${uid} ${func_code} ${start_addr} ${quantity} ${exception} ${data} ${expected_response}"
    ModbusSlaveLib.Add Expected Transaction    ${{eval($uid)}}    ${{eval($func_code)}}    ${{eval($start_addr)}}    ${{eval($quantity)}}    ${{eval($exception)}}    ${{eval('${data}')}}    ${{eval('${expected_response}')}}

    ${server_state} =    ModbusSlaveLib.Is Server Active
    IF    not ${server_state}
        Test Ensure Server Started    ${MODBUS_DEF_PORT}    ${timeout}    ${True}
    END

    # Get last processed transaction
    ${transaction} =    ModbusSlaveLib.Wait Transaction Data    timeout=${timeout}

    Should Not Be Empty    ${transaction.request}    No request received
    Should Not Be Empty    ${transaction.response}    No response sent

    # Verify the request
    ${ex_code} =    ModbusSlaveLib.Verify Expected Request    ${transaction.request}    ${uid}    ${func_code}    ${start_addr}    ${quantity}    ${exception}    ${data}
    Should Be Equal As Integers    ${exception}    ${ex_code}     Request verification failed

Test Start Verify Asynchronous
    [Arguments]    ${timeout}=${2}
    [Documentation]    Start Modbus answering machine with timeout and then check registered expectations

    ${expectations} =    Copy List    ${EXP_TRANSACTIONS}
    Test Ensure Server Started    ${MODBUS_DEF_PORT}    ${MODBUS_TIMEOUT}    ${True}

    ${result} =    ModbusSlaveLib.Verify Expectations     ${expectations}    ${timeout}
    IF    ${result} == ${0}
        Log    "All expectations met exp_length=${expectations.__len__()}"
    ELSE
        ${exp_length} =    Get length    ${expectations}
        IF    ${exp_length} == ${0}
            Log    "All expectations met, exp_length=${exp_length}"
        ELSE
            Log    "Status for following expectations (${exp_length}):"
            ${counter} =  Set Variable    ${0}
            FOR    ${i}    IN RANGE    ${exp_length}
                ${exp_transaction} =    Get From List    ${expectations}    ${i}
                Log    "Transaction state: ${exp_transaction.state}, exception: ${exp_transaction.exception}"
                IF    "${exp_transaction}" != "${None}" and "${exp_transaction.response}" != "${None}"
                    IF    "${exp_transaction.exception} == ${0}" and "${exp_transaction.state} == ${1}"
                        Log    "Expectation ${i} - PASS: Request: ${exp_transaction.request} | Response: ${exp_transaction.response}"
                    ELSE
                        Log    "Expectation ${i} - FAIL with ${exp_transaction.exception}: Request: ${exp_transaction.request} | Response: ${exp_transaction.response}"
                        ${counter} =    Set Variable    ${counter + 1}
                    END
                END
            END
            Run Keyword If    ${counter} > 0    Fail    "Found ${counter} failed expectations."
        END
    END
