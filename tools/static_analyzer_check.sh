#!/bin/bash

SCRIPT_DIR="$( cd "$(dirname "$0")" ; pwd -P )"

${IDF_PATH}/tools/idf_tools.py --non-interactive install esp-clang
export APPS=$( find . -type d ! -path "*build*" ! -path "*espressif__*" ! -path "*managed_components*" ! -path "*arch*" \
            \( -exec test -f '{}/CMakeLists.txt' \; -and -exec test -d '{}/main' \; -and -exec test -f '{}/main/CMakeLists.txt' \; \
            \) -print )

if [ $# -gt 1 ]; then
  echo "Incorrect number of parameters."
  exit 1
fi

echo "Found applications to check: ${APPS}"
for APP_DIR in ${APPS}
do
  pushd ${APP_DIR}
  case "$1" in
    "" | "clang")
      echo "CLANG build"
      export IDF_TOOLCHAIN="clang"
      . ${IDF_PATH}/export.sh
      echo "Clang check folder: ${PWD}, managed comp dir: ${APP_DIR}/managed_components"
      ${IDF_PATH}/tools/idf.py clang-check \
        --include-paths ${SCRIPT_DIR}/../modbus \
        --exclude-paths ./managed_components \
        --run-clang-tidy-py run-clang-tidy \
        --run-clang-tidy-options "-config-file=${SCRIPT_DIR}/.clang-tidy"
      ;;
    "gcc")
        rm -f sdkconfig
        export IDF_TOOLCHAIN="gcc"
        . ${IDF_PATH}/export.sh
        echo "GCC check folder: ${PWD}"
        echo "CONFIG_FMB_COMPILER_STATIC_ANALYZER_ENABLE=y" >> ${PWD}/sdkconfig.defaults
        idf.py set-target "esp32"
        idf.py build || die "CMake build in ${PWD} has failed"
        ;;
    *)
        echo "Incorrect parameter provided: $1, should be 'gcc' or 'clang'."
        exit 1
        ;;
  esac
  popd
done
