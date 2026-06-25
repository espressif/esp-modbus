#!/bin/sh

set -eu

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <component-name> <component-dir> <component-version> <api-token>"
    exit 1
fi

component_name="$1"
component_dir="$2"
component_version="$3"
component_token="$4"
component_env_key=$(printf '%s\n' "${component_name}" | tr '[:lower:]-' '[:upper:]_')
status_env_file="${COMPONENT_UPLOAD_STATUS_ENV:-component_upload_status.env}"
status_log_file="${COMPONENT_UPLOAD_STATUS_LOG:-component_upload_status.log}"

extract_upload_job_id() {
    sed -n 's/.*upload-status --job=\([0-9a-fA-F-]\{36\}\).*/\1/p' | tail -n 1
}

if [ ! -f "${component_dir}/idf_component.yml" ]; then
    echo "Component manifest was not found: ${component_dir}/idf_component.yml"
    exit 1
fi

if [ -z "${component_token}" ]; then
    echo "API token for espressif/${component_name}:${component_version} is required"
    exit 1
fi

echo "Uploading espressif/${component_name}:${component_version} from ${component_dir}"
export IDF_COMPONENT_API_TOKEN="${component_token}"

set +e
upload_output=$(
    cd "${component_dir}" &&
    compote component upload \
        --namespace=espressif \
        --name="${component_name}" \
        --allow-existing \
        --version="${component_version}" 2>&1
)
upload_exit_code=$?
set -e

printf '%s\n' "${upload_output}"
upload_job_id=$(printf '%s\n' "${upload_output}" | extract_upload_job_id)

{
    echo "${component_env_key}_VERSION=${component_version}"
    echo "${component_env_key}_UPLOAD_JOB_ID=${upload_job_id:-not_available}"
} >> "${status_env_file}"

{
    echo "## espressif/${component_name}:${component_version}"
    echo
    echo "### upload"
    printf '%s\n' "${upload_output}"
    echo
} >> "${status_log_file}"

if [ "${upload_exit_code}" -ne 0 ]; then
    echo "Upload failed for espressif/${component_name}:${component_version}"
    exit "${upload_exit_code}"
fi

if [ -z "${upload_job_id}" ]; then
    echo "No upload job ID was reported for espressif/${component_name}:${component_version}."
    echo "${component_env_key}_UPLOAD_STATUS_EXIT_CODE=not_checked" >> "${status_env_file}"
    {
        echo "### upload-status"
        echo "Not checked because the upload command did not report a job ID."
        echo
    } >> "${status_log_file}"
    exit 0
fi

echo "Checking upload status for espressif/${component_name}:${component_version}; job ${upload_job_id}"
set +e
upload_status_output=$(compote component upload-status --job="${upload_job_id}" 2>&1)
upload_status_exit_code=$?
set -e

printf '%s\n' "${upload_status_output}"
{
    echo "### upload-status"
    printf '%s\n' "${upload_status_output}"
    echo
} >> "${status_log_file}"
echo "${component_env_key}_UPLOAD_STATUS_EXIT_CODE=${upload_status_exit_code}" >> "${status_env_file}"

if [ "${upload_status_exit_code}" -ne 0 ]; then
    echo "Upload status check failed for espressif/${component_name}:${component_version}"
    exit "${upload_status_exit_code}"
fi
