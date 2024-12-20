# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=W0621  # redefined-outer-name

import logging
import os
import sys
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, Match, Optional, TextIO, Tuple

import pexpect
import pytest
from _pytest.fixtures import FixtureRequest
from _pytest.monkeypatch import MonkeyPatch
from pytest_embedded.plugin import multi_dut_argument, multi_dut_fixture
from pytest_embedded_idf.app import IdfApp
from pytest_embedded_idf.dut import IdfDut
from pytest_embedded_idf.serial import IdfSerial


class Stages(Enum):
    STACK_DEFAULT = 1
    STACK_IPV4 = 2
    STACK_IPV6 = 3
    STACK_INIT = 4
    STACK_CONNECT = 5
    STACK_START = 6
    STACK_PAR_OK = 7
    STACK_PAR_FAIL = 8
    STACK_DESTROY = 9

DEFAULT_SDKCONFIG = 'default'
ALLOWED_PERCENT_OF_FAILS = 10

class ModbusTestDut(IdfDut):

    TEST_IP_PROMPT = r'Waiting IP([0-9]{1,2}) from stdin:\r\r\n'
    TEST_IP_SET_CONFIRM = r'.*IP\([0-9]+\) = \[([0-9a-zA-Z\.\:]+)\] set from stdin.*'
    TEST_IP_ADDRESS_REGEXP = r'.*example_[a-z]+: .* IPv4 [a-z]+:.* ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*'
    TEST_APP_NAME = r'I \([0-9]+\) [a-z_]+: Project name:\s+([_a-z]*)'

    TEST_EXPECT_STR_TIMEOUT = 120
    TEST_ACK_TIMEOUT = 60
    TEST_MAX_CIDS = 8

    app: IdfApp
    serial: IdfSerial

    def __init__(self, *args, **kwargs) -> None:  # type: ignore
        super().__init__(*args, **kwargs)
        self.logger = logging.getLogger()
        self.test_output: Optional[TextIO] = None
        self.ip_address: Optional[str] = None
        self.app_name: Optional[str] = None
        self.param_fail_count = 0
        self.param_ok_count = 0
        self.test_stage = Stages.STACK_DEFAULT
        self.dictionary = None
        self.test_finish = False
        self.test_status = False

    def close(self) -> None:
        super().close()

    def dut_get_ip(self) -> Optional[str]:
        if self.ip_address is None:
            expect_address = self.expect(self.TEST_IP_ADDRESS_REGEXP, timeout=self.TEST_EXPECT_STR_TIMEOUT)
            if isinstance(expect_address, Match):
                self.ip_address = expect_address.group(1).decode('ascii')
        return self.ip_address

    def dut_get_name(self) -> Optional[str]:
        if self.app_name is None:
            expect_name = self.expect(self.TEST_APP_NAME, timeout=self.TEST_EXPECT_STR_TIMEOUT)
            if isinstance(expect_name, Match):
                self.app_name = expect_name.group(1).decode('ascii')
        return self.app_name

    def dut_send_ip(self, slave_ip: Optional[str]) -> Optional[int]:
        ''' The function sends the slave IP address defined as a parameter to master
        '''
        addr_num = 0
        self.expect(self.TEST_IP_PROMPT, timeout=self.TEST_ACK_TIMEOUT)
        if isinstance(slave_ip, str):
            for addr_num in range(0, self.TEST_MAX_CIDS):
                message = r'IP{}={}'.format(addr_num, slave_ip)
                self.logger.info('{} sent to master'.format(message))
                self.write(message)
        return addr_num

    def get_expect_proc(self) -> Optional[object]:
        expect_proc: object = None
        try:
            expect_proc = self.__getattribute__('pexpect_proc')
        except:
            expect_proc = self.__getattribute__('_p')
        finally:
            if (expect_proc and callable(getattr(expect_proc, 'expect'))):
                return expect_proc
            else :
                return None

    def expect_any(self, *expect_items: Tuple[str, Callable], timeout: Optional[int]) -> None:
        """
        expect_any(*expect_items, timeout=DEFAULT_TIMEOUT)
        expect any of the patterns.
        will call callback (if provided) if pattern match succeed and then return.
        will pass match result to the callback.

        :raise ExpectTimeout: failed to match any one of the expect items before timeout
        :raise UnsupportedExpectItem: pattern in expect_item is not string or compiled RegEx

        :arg expect_items: one or more expect items.
                           string, compiled RegEx pattern or (string or RegEx(string pattern), callback)
        :keyword timeout: timeout for expect
        :return: matched item
        """
        def process_expected_item(item_raw: Tuple[str, Callable[..., Any]]) -> Dict[str, Any]:
            # convert item raw data to standard dict
            item = {
                'pattern': item_raw[0] if isinstance(item_raw, tuple) else item_raw,
                'callback': item_raw[1] if isinstance(item_raw, tuple) else None,
                'index': -1,
                'ret': None,
            }
            return item

        expect_items_list = [process_expected_item(item) for item in expect_items]
        expect_patterns = [item['pattern'] for item in expect_items_list if item['pattern'] is not None]
        match_item = None

        # Workaround: We need to use the original expect method of pexpect process which returns 
        # index of matched pattern instead of Match object returned by dut.expect()
        expect_proc: Optional[object] = self.get_expect_proc()

        if expect_proc is not None:
            match_index = expect_proc.expect(expect_patterns, timeout)

            if isinstance(match_index, int):
                match_item = expect_items_list[match_index]  # type: ignore
                match_item['index'] = match_index  # type: ignore , keep match index 
                if isinstance(expect_proc.match, Match) and len(expect_proc.match.groups()) > 0:
                    match_item['ret'] = expect_proc.match.groups()
                if match_item['callback']:
                    match_item['callback'](match_item['ret'])  # execution of callback function
        else:
            self.logger.error('%s: failed to parse output. Please check component versions.', self.app_name)
            raise RuntimeError from None

    def dut_test_start(self, dictionary: Dict, timeout_value=TEST_EXPECT_STR_TIMEOUT) -> None:  # type: ignore
        """ The method to initialize and handle test stages
        """
        def handle_get_ip4(data: Optional[Any]) -> None:
            """ Handle get_ip v4
            """
            self.logger.info('%s[STACK_IPV4]: %s', self.app_name, str(data))
            self.test_stage = Stages.STACK_IPV4

        def handle_get_ip6(data: Optional[Any]) -> None:
            """ Handle get_ip v6
            """
            self.logger.info('%s[STACK_IPV6]: %s', self.app_name, str(data))
            self.test_stage = Stages.STACK_IPV6

        def handle_init(data: Optional[Any]) -> None:
            """ Handle init
            """
            self.logger.info('%s[STACK_INIT]: %s', self.app_name, str(data))
            self.test_stage = Stages.STACK_INIT

        def handle_connect(data: Optional[Any]) -> None:
            """ Handle connect
            """
            self.logger.info('%s[STACK_CONNECT]: %s', self.app_name, str(data))
            self.test_stage = Stages.STACK_CONNECT

        def handle_test_start(data: Optional[Any]) -> None:
            """ Handle connect
            """
            self.logger.info('%s[STACK_START]: %s', self.app_name, str(data))
            self.test_stage = Stages.STACK_START

        def handle_par_ok(data: Optional[Any]) -> None:
            """ Handle parameter ok
            """
            self.logger.info('%s[READ_PAR_OK]: %s', self.app_name, str(data))
            if self.test_stage.value >= Stages.STACK_START.value:
                self.param_ok_count += 1
            self.test_stage = Stages.STACK_PAR_OK

        def handle_par_fail(data: Optional[Any]) -> None:
            """ Handle parameter fail
            """
            self.logger.info('%s[READ_PAR_FAIL]: %s', self.app_name, str(data))
            self.param_fail_count += 1
            self.test_stage = Stages.STACK_PAR_FAIL

        def handle_destroy(data: Optional[Any]) -> None:
            """ Handle destroy
            """
            self.logger.info('%s[%s]: %s', self.app_name, Stages.STACK_DESTROY.name, str(data))
            self.test_stage = Stages.STACK_DESTROY
            self.test_finish = True

        while not self.test_finish:
            try:
                self.expect_any((dictionary[Stages.STACK_IPV4], handle_get_ip4),
                                (dictionary[Stages.STACK_IPV6], handle_get_ip6),
                                (dictionary[Stages.STACK_INIT], handle_init),
                                (dictionary[Stages.STACK_CONNECT], handle_connect),
                                (dictionary[Stages.STACK_START], handle_test_start),
                                (dictionary[Stages.STACK_PAR_OK], handle_par_ok),
                                (dictionary[Stages.STACK_PAR_FAIL], handle_par_fail),
                                (dictionary[Stages.STACK_DESTROY], handle_destroy),
                                timeout=timeout_value)
            except pexpect.TIMEOUT:
                self.logger.info('%s, expect timeout on stage %s (%s seconds)', self.app_name, self.test_stage.name, timeout_value)
                self.test_finish = True

    def dut_check_errors(self) -> None:
        ''' Verify allowed percentage of errors for the dut 
        '''
        allowed_ok_percentage = ((self.param_ok_count / (self.param_ok_count + self.param_fail_count + 1)) * 100)
        if self.param_ok_count and (allowed_ok_percentage > (100 - ALLOWED_PERCENT_OF_FAILS)):
            self.logger.info('%s: ok_count: %d, fail count: %d', self.app_name, self.param_ok_count, self.param_fail_count)
        else :
            self.logger.error('%s: ok_count: %d, number of failed readings %d exceeds %d percent', self.app_name, self.param_ok_count, self.param_fail_count, ALLOWED_PERCENT_OF_FAILS)
            raise RuntimeError from None

############
# Fixtures #
############

@pytest.fixture(scope='session', autouse=True)
def session_tempdir() -> str:
    
    _tmpdir = os.path.join(
        os.path.dirname(__file__),
        'pytest_embedded_log',
        datetime.now().strftime('%Y-%m-%d_%H-%M-%S'),
    )
    os.makedirs(_tmpdir, exist_ok=True)
    return _tmpdir


@pytest.fixture(autouse=True)
@multi_dut_fixture
def junit_properties(
    test_case_name: str, record_xml_attribute: Callable[[str, object], None]
) -> None:
    """
    This fixture is autoused and will modify the junit report test case name to <target>.<config>.<case_name>
    """
    record_xml_attribute('name', test_case_name)


@pytest.fixture(scope='module')
def monkeypatch_module(request: FixtureRequest) -> MonkeyPatch:
    mp = MonkeyPatch()
    request.addfinalizer(mp.undo)
    return mp


@pytest.fixture(scope='module', autouse=True)
def replace_dut_class(monkeypatch_module: MonkeyPatch) -> None:
    monkeypatch_module.setattr('pytest_embedded_idf.IdfDut', ModbusTestDut)


@pytest.fixture
@multi_dut_argument
def config(request: FixtureRequest) -> str:
    return getattr(request, 'param', None) or DEFAULT_SDKCONFIG


@pytest.fixture
@multi_dut_fixture
def build_dir(app_path: str, target: Optional[str], config: Optional[str]) -> str:
    """
    Check local build dir with the following priority:

    1. build_<target>_<config>
    2. build_<target>
    3. build_<config>
    4. build

    Args:
        app_path: app path
        target: target
        config: config

    Returns:
        valid build directory
    """
    check_dirs = []

    if target is not None and config is not None:
        check_dirs.append(f'build_{target}_{config}')
    if target is not None:
        check_dirs.append(f'build_{target}')
    if config is not None:
        check_dirs.append(f'build_{config}')
    check_dirs.append('build')

    for check_dir in check_dirs:
        binary_path = os.path.join(app_path, check_dir)
        if os.path.isdir(binary_path):
            logging.info(f'find valid binary path: {binary_path}')
            return check_dir

        logging.warning(
            'checking binary path: %s... missing... try another place', binary_path
        )

    if config is not None and 'dummy' in config:
        logging.warning('no build dir valid for application: %s, config: %s. Skip test.', binary_path, config)
        return None

    recommend_place = check_dirs[0]
    logging.error(
        f'no build dir valid. Please build the binary via "idf.py -B {recommend_place} build" and run pytest again'
    )

    sys.exit(1)
