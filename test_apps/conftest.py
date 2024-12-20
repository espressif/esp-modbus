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
from pytest_embedded_idf import CaseTester
from _pytest.config import Config
from _pytest.fixtures import FixtureRequest
from _pytest.monkeypatch import MonkeyPatch
from pytest_embedded.plugin import multi_dut_argument, multi_dut_fixture
from pytest_embedded_idf.app import IdfApp
from pytest_embedded_idf.dut import IdfDut
from pytest_embedded_idf.serial import IdfSerial

DEFAULT_SDKCONFIG = 'default'


############
# Fixtures #
############


@pytest.fixture
def case_tester(dut: IdfDut, **kwargs):  # type: ignore
    yield CaseTester(dut, **kwargs)


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

    recommend_place = check_dirs[0]
    logging.error(
        f'no build dir valid. Please build the binary via "idf.py -B {recommend_place} build" and run pytest again'
    )
    sys.exit(1)
