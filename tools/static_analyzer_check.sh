#!/bin/bash

SCRIPT_DIR="$( cd "$(dirname "$0")" ; pwd -P )"

die() {
  local exit_code=$1
  shift
  [[ $exit_code ]] &&               # do nothing if no error code passed
    ((exit_code != 0)) && {         # do nothing if error code is 0
      printf 'ERROR: %s\n' "$@" >&2
      exit "$exit_code"
    }
}

${IDF_PATH}/tools/idf_tools.py --non-interactive install esp-clang
# unit_tests stay out of this check.
export APPS=$( find . -type d ! -path "*build*" ! -path "*espressif__*" ! -path "*managed_components*" ! -path "*arch*" ! -path "*unit_tests*" \
            \( -exec test -f '{}/CMakeLists.txt' \; -and -exec test -d '{}/main' \; -and -exec test -f '{}/main/CMakeLists.txt' \; \
            \) -print )

if [ $# -gt 1 ]; then
  die $? "Incorrect number of parameters."
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
      # Use a separate build dir so clang-tidy never reads a GCC compile_commands.json
      ${IDF_PATH}/tools/idf.py -B build_clang clang-check \
        --include-paths ${SCRIPT_DIR}/../modbus \
        --exclude-paths ./managed_components \
        --run-clang-tidy-py run-clang-tidy \
        --exit-code \
        --run-clang-tidy-options "-config-file=${SCRIPT_DIR}/.clang-tidy" \
        || die 2 "Clang check in ${PWD} has failed"
      ;;
    "gcc")
        rm -f sdkconfig
        export IDF_TOOLCHAIN="gcc"
        . ${IDF_PATH}/export.sh
        echo "GCC check folder: ${PWD}"
        grep -q '^CONFIG_FMB_COMPILER_STATIC_ANALYZER_ENABLE=y' "${PWD}/sdkconfig.defaults" 2>/dev/null \
            || echo "CONFIG_FMB_COMPILER_STATIC_ANALYZER_ENABLE=y" >> "${PWD}/sdkconfig.defaults"
        idf.py -B build set-target "esp32"
        idf.py -B build build || die 2 "CMake build in ${PWD} has failed"
        ;;
    *)
        die 2 "Incorrect parameter provided: $1, should be 'gcc' or 'clang'."
        ;;
  esac
  popd
done
