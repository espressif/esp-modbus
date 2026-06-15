#!/bin/bash

ROOT_DIR="$( cd "$(dirname "$0")/../" ; pwd -P )"

# Parse parameters: require at least key and value, optional file mask
if [ $# -lt 2 ] || [ $# -gt 6 ]; then
  echo "Parameters provided: $#, $@, Usage: $0 CONFIG_KEY KEY_VALUE [CONFIG_MASK] "
  echo "Example: $0 CONFIG_FMB_SETUP_DEBUG_MESSAGING y 'sdkconfig.ci.*'"
  exit 1
fi

echo "Script called with $# parameters: $@"
echo "Root project path: ${ROOT_DIR}"

KEY="${1:-CONFIG_FMB_SETUP_DEBUG_MESSAGING}"
VALUE="${2:-y}"
FILE_PATTERN="${3:-sdkconfig.*}" # default mask if not provided

export APPS=$( find "${ROOT_DIR}" -type d ! -path "build_*" ! -path "*espressif__*" ! -path "managed_components*" ! -path "*arch*" \
            \( -exec test -f '{}/CMakeLists.txt' \; -and \
               -exec test -d '{}/main' \; -and \
               -exec test -f '{}/main/CMakeLists.txt' \; \
            \) -print )

echo "Found applications to check: ${APPS}"
for APP_DIR in ${APPS}
do
  pushd ${APP_DIR}
  echo "Checking for files matching: ${APP_DIR}/${FILE_PATTERN}"
  shopt -s nullglob
  matches=( ${FILE_PATTERN} )
  if [ ${#matches[@]} -eq 0 ]; then
    echo "No matching files in ${APP_DIR}"
  else
    for FILE in "${matches[@]}"; do
      echo "Found file: ${APP_DIR}/${FILE}"
      if grep -q "^${KEY}=" "${FILE}"; then
        echo "Updating ${KEY} in ${FILE} to ${VALUE}"
        # use '|' delimiter to allow slashes in VALUE
        sed -i "s|^${KEY}=.*|${KEY}=${VALUE}|" "${FILE}"
      else
        echo "Setting ${KEY} in ${FILE} to ${VALUE}"
        echo "${KEY}=${VALUE}" >> "${FILE}"
      fi
    done
  fi
  shopt -u nullglob
  popd
done
