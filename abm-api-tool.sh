#!/bin/zsh

# Apple Business Manager API Tool
# A comprehensive zsh script for interfacing with the Apple Business Manager API
# 
# SECURITY: API credentials must be provided via environment variables or Jamf parameters
# USAGE: Can be run standalone, from Jamf policies, or as a utility script
#
# Author: David 'Bing' Crosby
# Version: 3.0
# Date: 2024-06-10
# License: GNU General Public License v3.0

# This script is provided "as is" without warranty of any kind.
# Use at your own risk.

# ============================================================================
# PREAMBLE
# ============================================================================

# Enable strict error handling
set -euo pipefail

# ============================================================================
# CONFIGURATION AND CONSTANTS
# ============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly LOG_FILE="/tmp/${SCRIPT_NAME%.*}.log"

# Apple Business Manager API Configuration
readonly ABM_BASE_URL="https://api-business.apple.com/v1"
readonly OAUTH_TOKEN_URL="https://account.apple.com/auth/oauth2/token"
readonly RATE_LIMIT=100  # requests per second
readonly DEFAULT_PAGE_SIZE=100

# Colours for output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# ============================================================================
# LOGGING AND UTILITY FUNCTIONS
# ============================================================================

log() {
    local level="$1"
    shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $*" | tee -a "$LOG_FILE" >&2
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { 
    [[ "${DEBUG:-}" == "1" ]] && log "DEBUG" "$@" || true
}

print_success() { printf "${GREEN}✓ %s${NC}\n" "$*" >&2; }
print_error() { printf "${RED}✗ %s${NC}\n" "$*" >&2; }
print_warning() { printf "${YELLOW}⚠ %s${NC}\n" "$*" >&2; }
print_info() { printf "${BLUE}ℹ %s${NC}\n" "$*" >&2; }

cleanup() {
    local exit_code=$?
    log_info "Script execution completed with exit code: $exit_code"
    exit $exit_code
}
trap cleanup EXIT

usage() {
    printf "${GREEN}Apple Business Manager API Tool${NC}\n\n"
    
    printf "${BLUE}USAGE:${NC}\n"
    printf "    %s <command> [options]\n\n" "$SCRIPT_NAME"
    
    printf "${BLUE}COMMANDS:${NC}\n"
    printf "    list-devices [--format json|table] [--filter active|inactive|all] [--limit N]\n"
    printf "        List all organisational devices\n"
    printf "        \n"
    printf "    device-details <device-id> [--format json|table]\n"
    printf "        Get detailed information for a specific device\n"
    printf "        \n"
    printf "    delete-device <device-id> [--confirm]\n"
    printf "        Remove a device from Apple Business Manager\n"
    printf "        \n"
    printf "    move-device <device-id> <target-mdm-server-id> [--confirm]\n"
    printf "        Move a device from one MDM to another\n"
    printf "        \n"
    printf "    list-mdm-servers [--format json|table]\n"
    printf "        List all registered MDM servers\n"
    printf "        \n"
    printf "    validate-credentials\n"
    printf "        Test API connectivity and authentication\n\n"

    printf "${BLUE}OPTIONS:${NC}\n"
    printf "    --format json|table     Output format (default: table)\n"
    printf "    --filter active|inactive|all    Filter devices by status (default: all)\n"
    printf "    --limit N               Limit number of results (default: 100)\n"
    printf "    --confirm               Skip confirmation prompts\n"
    printf "    --debug                 Enable debug logging\n"
    printf "    --help                  Show this help message\n\n"

    printf "${BLUE}ENVIRONMENT VARIABLES:${NC}\n"
    printf "    ABM_CLIENT_ID           Apple Business Manager API Client ID\n"
    printf "    ABM_PRIVATE_KEY_PATH    Path to the private key (.pem file)\n"
    printf "    ABM_KEY_ID              Key ID from Apple Business Manager\n\n"

    printf "${BLUE}JAMF PARAMETERS:${NC}\n"
    printf "    \$4 = ABM_CLIENT_ID\n"
    printf "    \$5 = ABM_PRIVATE_KEY_PATH\n"  
    printf "    \$6 = ABM_KEY_ID\n\n"

    printf "${BLUE}EXAMPLES:${NC}\n"
    printf "    # List all devices in table format\n"
    printf "    %s list-devices --format table\n" "$SCRIPT_NAME"
    printf "    \n"
    printf "    # Get details for a specific device\n"
    printf "    %s device-details \"ABC123DEF456\"\n" "$SCRIPT_NAME"
    printf "    \n"
    printf "    # Move device to different MDM server\n"
    printf "    %s move-device \"ABC123DEF456\" \"mdm-server-123\" --confirm\n" "$SCRIPT_NAME"
    printf "    \n"
    printf "    # Delete a device (with confirmation)\n"
    printf "    %s delete-device \"ABC123DEF456\"\n" "$SCRIPT_NAME"
    printf "\n"
}

# ============================================================================
# CREDENTIAL MANAGEMENT
# ============================================================================

load_credentials() {
    log_info "Loading API credentials..."
    
    # Check if running from Jamf (parameters $4, $5, $6)
    if [[ -n "${4:-}" && -n "${5:-}" && -n "${6:-}" ]]; then
        log_info "Loading credentials from Jamf parameters"
        ABM_CLIENT_ID="$4"
        ABM_PRIVATE_KEY_PATH="$5"
        ABM_KEY_ID="$6"
    # Check environment variables
    elif [[ -n "${ABM_CLIENT_ID:-}" && -n "${ABM_PRIVATE_KEY_PATH:-}" && -n "${ABM_KEY_ID:-}" ]]; then
        log_info "Loading credentials from environment variables"
        # Variables already set from environment
    else
        print_error "Missing required credentials. Please set environment variables or provide Jamf parameters."
        log_error "Required: ABM_CLIENT_ID, ABM_PRIVATE_KEY_PATH, ABM_KEY_ID"
        return 1
    fi
    
    # Validate credentials exist and are accessible
    if [[ ! -f "$ABM_PRIVATE_KEY_PATH" ]]; then
        print_error "Private key file not found: $ABM_PRIVATE_KEY_PATH"
        return 1
    fi
    
    if [[ ! -r "$ABM_PRIVATE_KEY_PATH" ]]; then
        print_error "Cannot read private key file: $ABM_PRIVATE_KEY_PATH"
        return 1
    fi
    
    log_info "Credentials loaded successfully"
    return 0
}

# ============================================================================
# JWT AND OAUTH AUTHENTICATION
# ============================================================================

generate_jwt() {
    log_debug "Generating JWT for authentication"
    
    local current_time=$(date +%s)
    local expiry_time=$((current_time + 3600)) # 1 hour from now
    local jti=$(uuidgen | tr '[:upper:]' '[:lower:]')
    
    # Verify key file exists and is readable
    if [[ ! -r "$ABM_PRIVATE_KEY_PATH" ]]; then
        log_error "Cannot read private key file: $ABM_PRIVATE_KEY_PATH"
        return 1
    fi
    
    log_debug "Using Client ID: BUSINESSAPI.${ABM_CLIENT_ID}"
    log_debug "Using Key ID: ${ABM_KEY_ID}"
    log_debug "JWT will expire at: $expiry_time (current: $current_time)"
    
    # JWT Header
    local header=$(printf '{"alg":"ES256","kid":"%s","typ":"JWT"}' "$ABM_KEY_ID" | base64 | tr -d '=\n' | tr '+/' '-_')
    
    # JWT Payload - Note: sub and iss should be the FULL client ID including BUSINESSAPI prefix
    local payload=$(printf '{"sub":"BUSINESSAPI.%s","aud":"%s","iat":%d,"exp":%d,"jti":"%s","iss":"BUSINESSAPI.%s"}' \
        "$ABM_CLIENT_ID" "$OAUTH_TOKEN_URL" "$current_time" "$expiry_time" "$jti" "$ABM_CLIENT_ID" | \
        base64 | tr -d '=\n' | tr '+/' '-_')
    
    # Sign the JWT
    local unsigned_token="${header}.${payload}"
    local signature
    signature=$(printf '%s' "$unsigned_token" | \
        openssl dgst -sha256 -sign "$ABM_PRIVATE_KEY_PATH" | \
        base64 | tr -d '=\n' | tr '+/' '-_') || {
        log_error "Failed to sign JWT with private key"
        return 1
    }
    
    local jwt="${header}.${payload}.${signature}"
    log_debug "JWT header: $header"
    log_debug "JWT payload: $payload"
    log_debug "Generated JWT: ${jwt:0:100}..."
    
    printf '%s' "$jwt"
}

get_access_token() {
    log_debug "=== Starting get_access_token function ==="
    log_debug "DEBUG variable: ${DEBUG:-unset}"
    log_debug "Requesting OAuth access token"
    
    # Ensure client ID has proper format (add BUSINESSAPI. prefix if not present)
    local full_client_id
    if [[ "$ABM_CLIENT_ID" == BUSINESSAPI.* ]]; then
        full_client_id="$ABM_CLIENT_ID"
        log_debug "Client ID already has BUSINESSAPI prefix: ${ABM_CLIENT_ID}"
    else
        full_client_id="BUSINESSAPI.${ABM_CLIENT_ID}"
        log_debug "Added BUSINESSAPI prefix to client ID: ${ABM_CLIENT_ID} -> ${full_client_id}"
    fi
    
    log_debug "Resolved Client ID: ${full_client_id}"
    log_debug "About to call generate_jwt with parameter: '${full_client_id}'"
    
    local jwt
    jwt=$(generate_jwt "$full_client_id") || {
        log_error "Failed to generate JWT"
        return 1
    }
    
    log_debug "Generated JWT: ${jwt:0:50}..."
    
    # Construct the request URL with parameters (Apple's preferred format)
    local token_url="${OAUTH_TOKEN_URL}?grant_type=client_credentials&client_id=${full_client_id}&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=${jwt}&scope=business.api"
    
    log_debug "Making token request to: ${OAUTH_TOKEN_URL}"
    log_debug "Client ID for HTTP request: ${full_client_id}"
    log_debug "JWT length: ${#jwt} characters"
    
    # Make the request with verbose output in debug mode
    local curl_cmd=(
        curl -s -X POST
        -H "Host: account.apple.com"
        -H "Content-Type: application/x-www-form-urlencoded"
    )
    
    # Add verbose flag if debug is enabled
    if [[ "${DEBUG:-}" == "1" ]]; then
        curl_cmd+=(-v)
        log_debug "Making verbose curl request"
    fi
    
    curl_cmd+=("$token_url")
    
    log_debug "About to execute curl command"
    local response
    response=$("${curl_cmd[@]}" 2>&1) || {
        log_error "Failed to request access token - curl error"
        if [[ "${DEBUG:-}" == "1" ]]; then
            log_debug "Curl output: $response"
        fi
        return 1
    }
    
    log_debug "Curl command completed"
    
    # In debug mode, show the full response
    if [[ "${DEBUG:-}" == "1" ]]; then
        log_debug "Full curl response: $response"
        # Extract just the JSON part (after the verbose headers)
        local json_response
        json_response=$(echo "$response" | tail -n 1)
        log_debug "JSON response: $json_response"
        response="$json_response"
    fi
    
    log_debug "About to validate JSON response"
    
    # Check if response is valid JSON
    if ! echo "$response" | jq . >/dev/null 2>&1; then
        log_error "Invalid JSON response received"
        log_debug "Raw response: $response"
        return 1
    fi
    
    log_debug "JSON is valid, checking for errors"
    
    # Check if response contains an error
    if echo "$response" | jq -e '.error' >/dev/null 2>&1; then
        local error_msg
        error_msg=$(echo "$response" | jq -r '.error_description // .error')
        log_error "OAuth error: $error_msg"
        if [[ "${DEBUG:-}" == "1" ]]; then
            log_debug "Full error response: $response"
        fi
        return 1
    fi
    
    log_debug "No errors found, extracting access token"
    
    # Extract access token
    local access_token
    access_token=$(echo "$response" | jq -r '.access_token // empty') || {
        log_error "Failed to parse access token from response"
        log_debug "Response: $response"
        return 1
    }
    
    if [[ -z "$access_token" ]]; then
        log_error "No access token received"
        log_debug "Response: $response"
        return 1
    fi
    
    log_debug "Access token received: ${access_token:0:20}..."
    printf '%s' "$access_token"
}

# ============================================================================
# API REQUEST FUNCTIONS
# ============================================================================

make_api_request() {
    local method="$1"
    local endpoint="$2"
    local access_token="$3"
    local data="${4:-}"
    
    log_debug "Making API request: $method $endpoint"
    
    local curl_args=(
        -s -w "%{http_code}"
        -X "$method"
        -H "Authorization: Bearer $access_token"
        -H "Content-Type: application/json"
        -H "Accept: application/json"
    )
    
    if [[ -n "$data" ]]; then
        curl_args+=(-d "$data")
    fi
    
    local response
    response=$(curl "${curl_args[@]}" "${ABM_BASE_URL}${endpoint}")
    
    local http_code="${response: -3}"
    local body="${response%???}"
    
    log_debug "HTTP Status: $http_code"
    
    case "$http_code" in
        200|201|204)
            printf '%s' "$body"
            return 0
            ;;
        401)
            log_error "Authentication failed (401)"
            return 1
            ;;
        403)
            log_error "Access forbidden (403)"
            return 1
            ;;
        404)
            log_error "Resource not found (404)"
            return 1
            ;;
        429)
            log_error "Rate limit exceeded (429)"
            return 1
            ;;
        *)
            log_error "API request failed with HTTP $http_code"
            log_debug "Response body: $body"
            return 1
            ;;
    esac
}

# ============================================================================
# DEVICE MANAGEMENT FUNCTIONS
# ============================================================================

list_devices() {
    local format="${1:-table}"
    local filter="${2:-all}"
    local limit="${3:-$DEFAULT_PAGE_SIZE}"
    
    log_info "Listing devices (format: $format, filter: $filter, limit: $limit)"
    
    local access_token
    access_token=$(get_access_token) || {
        print_error "Failed to get access token"
        return 1
    }
    
    local endpoint="/orgDevices?limit=$limit"
    case "$filter" in
        active) endpoint+="&filter[status]=active" ;;
        inactive) endpoint+="&filter[status]=inactive" ;;
        all) ;; # No filter needed
    esac
    
    local response
    response=$(make_api_request "GET" "$endpoint" "$access_token") || {
        print_error "Failed to retrieve device list"
        return 1
    }
    
    case "$format" in
        json)
            echo "$response" | jq '.'
            ;;
        table)
            format_device_table "$response"
            ;;
    esac
}

get_device_details() {
    local device_id="$1"
    local format="${2:-table}"
    
    log_info "Getting details for device: $device_id"
    
    local access_token
    access_token=$(get_access_token) || {
        print_error "Failed to get access token"
        return 1
    }
    
    local response
    response=$(make_api_request "GET" "/orgDevices/$device_id" "$access_token") || {
        print_error "Failed to retrieve device details"
        return 1
    }
    
    case "$format" in
        json)
            echo "$response" | jq '.'
            ;;
        table)
            format_device_details "$response"
            ;;
    esac
}

delete_device() {
    local device_id="$1"
    local confirm="${2:-false}"
    
    log_info "Preparing to delete device: $device_id"
    
    if [[ "$confirm" != "true" ]]; then
        printf "Are you sure you want to delete device %s? (y/N): " "$device_id"
        read -r response
        case "$response" in
            [Yy]|[Yy][Ee][Ss]) ;;
            *) 
                print_info "Delete cancelled"
                return 0
                ;;
        esac
    fi
    
    local access_token
    access_token=$(get_access_token) || {
        print_error "Failed to get access token"
        return 1
    }
    
    # Create device activity for deletion/unassignment
    local activity_data
    activity_data=$(printf '{"data":{"type":"orgDeviceActivities","attributes":{"action":"unassign"},"relationships":{"devices":{"data":[{"type":"orgDevices","id":"%s"}]}}}}' "$device_id")
    
    local response
    response=$(make_api_request "POST" "/orgDeviceActivities" "$access_token" "$activity_data") || {
        print_error "Failed to delete device"
        return 1
    }
    
    print_success "Device $device_id has been successfully removed from Apple Business Manager"
}

move_device() {
    local device_id="$1"
    local target_mdm_id="$2"
    local confirm="${3:-false}"
    
    log_info "Preparing to move device $device_id to MDM server $target_mdm_id"
    
    if [[ "$confirm" != "true" ]]; then
        printf "Are you sure you want to move device %s to MDM server %s? (y/N): " "$device_id" "$target_mdm_id"
        read -r response
        case "$response" in
            [Yy]|[Yy][Ee][Ss]) ;;
            *) 
                print_info "Move cancelled"
                return 0
                ;;
        esac
    fi
    
    local access_token
    access_token=$(get_access_token) || {
        print_error "Failed to get access token"
        return 1
    }
    
    # Create device activity for MDM assignment
    local activity_data
    activity_data=$(printf '{"data":{"type":"orgDeviceActivities","attributes":{"action":"assign"},"relationships":{"devices":{"data":[{"type":"orgDevices","id":"%s"}]},"mdmServer":{"data":{"type":"mdmServers","id":"%s"}}}}}' "$device_id" "$target_mdm_id")
    
    local response
    response=$(make_api_request "POST" "/orgDeviceActivities" "$access_token" "$activity_data") || {
        print_error "Failed to move device"
        return 1
    }
    
    print_success "Device $device_id has been successfully moved to MDM server $target_mdm_id"
}

list_mdm_servers() {
    local format="${1:-table}"
    
    log_info "Listing MDM servers (format: $format)"
    
    local access_token
    access_token=$(get_access_token) || {
        print_error "Failed to get access token"
        return 1
    }
    
    local response
    response=$(make_api_request "GET" "/mdmServers" "$access_token") || {
        print_error "Failed to retrieve MDM server list"
        return 1
    }
    
    case "$format" in
        json)
            echo "$response" | jq '.'
            ;;
        table)
            format_mdm_server_table "$response"
            ;;
    esac
}

validate_credentials() {
    log_info "Validating API credentials and connectivity"
    
    print_info "Testing credential loading..."
    load_credentials || {
        print_error "Credential validation failed"
        return 1
    }
    print_success "Credentials loaded successfully"
    
    # Verify private key is EC format
    print_info "Validating private key format..."
    if ! openssl ec -in "$ABM_PRIVATE_KEY_PATH" -noout 2>/dev/null; then
        print_error "Private key is not in EC (Elliptic Curve) format"
        log_error "Apple Business Manager requires EC private keys for ES256 signing"
        return 1
    fi
    print_success "Private key format validated (EC)"
    
    print_info "Testing JWT generation..."
    local access_token
    access_token=$(get_access_token) || {
        print_error "OAuth token retrieval failed"
        log_error "get_access_token returned non-zero exit code"
        return 1
    }
    print_success "Access token retrieved successfully"
    log_debug "Token: ${access_token:0:20}..."
    
    print_info "Testing API connectivity..."
    local response
    response=$(make_api_request "GET" "/mdmServers" "$access_token") || {
        print_error "API connectivity test failed"
        return 1
    }
    print_success "API connectivity test passed"
    
    print_success "All credential validation tests passed"
}

# ============================================================================
# OUTPUT FORMATTING FUNCTIONS
# ============================================================================

format_device_table() {
    local json_data="$1"
    
    # Check if we have devices
    local device_count
    device_count=$(echo "$json_data" | jq '.data | length')
    
    if [[ "$device_count" -eq 0 ]]; then
        echo "No devices found"
        return 0
    fi
    
    # Print header
    printf "%-20s %-15s %-20s %-10s %-30s\n" "Device ID" "Serial Number" "Model" "Status" "MDM Server"
    printf "%s\n" "$(printf '%.0s-' {1..95})"
    
    # Process each device
    echo "$json_data" | jq -r '.data[] | 
        [
            .id // "N/A",
            .attributes.serialNumber // "N/A", 
            .attributes.model // "N/A",
            .attributes.profileStatus // "N/A",
            (.relationships.assignedServer.data.id // "Unassigned")
        ] | @tsv' | \
    while IFS=$'\t' read -r device_id serial model status mdm_server; do
        printf "%-20s %-15s %-20s %-10s %-30s\n" "$device_id" "$serial" "$model" "$status" "$mdm_server"
    done
}

format_device_details() {
    local json_data="$1"
    
    echo "Device Details:"
    echo "$(printf '%.0s=' {1..50})"
    
    # Extract device information using jq
    local device_id serial model color status os_version device_family purchase_date warranty_end mdm_server_id
    
    device_id=$(echo "$json_data" | jq -r '.data.id // "N/A"')
    serial=$(echo "$json_data" | jq -r '.data.attributes.serialNumber // "N/A"')
    model=$(echo "$json_data" | jq -r '.data.attributes.model // "N/A"')
    color=$(echo "$json_data" | jq -r '.data.attributes.color // "N/A"')
    status=$(echo "$json_data" | jq -r '.data.attributes.profileStatus // "N/A"')
    os_version=$(echo "$json_data" | jq -r '.data.attributes.osVersion // "N/A"')
    device_family=$(echo "$json_data" | jq -r '.data.attributes.deviceFamily // "N/A"')
    purchase_date=$(echo "$json_data" | jq -r '.data.attributes.purchaseDate // empty')
    warranty_end=$(echo "$json_data" | jq -r '.data.attributes.warrantyEndDate // empty')
    mdm_server_id=$(echo "$json_data" | jq -r '.data.relationships.assignedServer.data.id // "Unassigned"')
    
    printf "Device ID:      %s\n" "$device_id"
    printf "Serial Number:  %s\n" "$serial"
    printf "Model:          %s\n" "$model"
    printf "Color:          %s\n" "$color"
    printf "Status:         %s\n" "$status"
    printf "OS Version:     %s\n" "$os_version"
    printf "Device Family:  %s\n" "$device_family"
    
    # Optional fields
    [[ -n "$purchase_date" ]] && printf "Purchase Date:  %s\n" "$purchase_date"
    [[ -n "$warranty_end" ]] && printf "Warranty End:   %s\n" "$warranty_end"
    
    printf "MDM Server ID:  %s\n" "$mdm_server_id"
}

format_mdm_server_table() {
    local json_data="$1"
    
    # Check if we have servers
    local server_count
    server_count=$(echo "$json_data" | jq '.data | length')
    
    if [[ "$server_count" -eq 0 ]]; then
        echo "No MDM servers found"
        return 0
    fi
    
    # Print header
    printf "%-30s %-40s %-50s\n" "Server ID" "Name" "URL"
    printf "%s\n" "$(printf '%.0s-' {1..120})"
    
    # Process each server
    echo "$json_data" | jq -r '.data[] | 
        [
            .id // "N/A",
            .attributes.name // "N/A",
            .attributes.url // "N/A"
        ] | @tsv' | \
    while IFS=$'\t' read -r server_id name url; do
        printf "%-30s %-40s %-50s\n" "$server_id" "$name" "$url"
    done
}

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

main() {
    # Check dependencies
    local missing_deps=()
    
    command -v curl >/dev/null 2>&1 || missing_deps+=("curl")
    command -v jq >/dev/null 2>&1 || missing_deps+=("jq")
    command -v openssl >/dev/null 2>&1 || missing_deps+=("openssl")
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"
        print_info "Please install the missing dependencies and try again"
        return 1
    fi
    
    # Parse global options
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug)
                DEBUG=1
                shift
                ;;
            --help)
                usage
                return 0
                ;;
            *)
                break
                ;;
        esac
    done
    
    if [[ $# -eq 0 ]]; then
        usage
        return 1
    fi
    
    # Load credentials
    load_credentials || return 1
    
    # Parse commands
    local command="$1"
    shift
    
    case "$command" in
        list-devices)
            local format="table"
            local filter="all"
            local limit="$DEFAULT_PAGE_SIZE"
            
            while [[ $# -gt 0 ]]; do
                case $1 in
                    --format)
                        format="$2"
                        shift 2
                        ;;
                    --filter)
                        filter="$2"
                        shift 2
                        ;;
                    --limit)
                        limit="$2"
                        shift 2
                        ;;
                    --debug)
                        DEBUG=1
                        log_debug "Debug mode enabled"
                        shift
                        ;;
                    *)
                        print_error "Unknown option for list-devices: $1"
                        return 1
                        ;;
                esac
            done
            
            list_devices "$format" "$filter" "$limit"
            ;;
            
        device-details)
            if [[ $# -eq 0 ]]; then
                print_error "Device ID required for device-details command"
                return 1
            fi
            
            local device_id="$1"
            local format="table"
            shift
            
            while [[ $# -gt 0 ]]; do
                case $1 in
                    --format)
                        format="$2"
                        shift 2
                        ;;
                    --debug)
                        DEBUG=1
                        log_debug "Debug mode enabled"
                        shift
                        ;;
                    *)
                        print_error "Unknown option for device-details: $1"
                        return 1
                        ;;
                esac
            done
            
            get_device_details "$device_id" "$format"
            ;;
            
        delete-device)
            if [[ $# -eq 0 ]]; then
                print_error "Device ID required for delete-device command"
                return 1
            fi
            
            local device_id="$1"
            local confirm="false"
            shift
            
            while [[ $# -gt 0 ]]; do
                case $1 in
                    --confirm)
                        confirm="true"
                        shift
                        ;;
                    --debug)
                        DEBUG=1
                        log_debug "Debug mode enabled"
                        shift
                        ;;
                    *)
                        print_error "Unknown option for delete-device: $1"
                        return 1
                        ;;
                esac
            done
            
            delete_device "$device_id" "$confirm"
            ;;
            
        move-device)
            if [[ $# -lt 2 ]]; then
                print_error "Device ID and target MDM server ID required for move-device command"
                return 1
            fi
            
            local device_id="$1"
            local target_mdm_id="$2"
            local confirm="false"
            shift 2
            
            while [[ $# -gt 0 ]]; do
                case $1 in
                    --confirm)
                        confirm="true"
                        shift
                        ;;
                    --debug)
                        DEBUG=1
                        log_debug "Debug mode enabled"
                        shift
                        ;;
                    *)
                        print_error "Unknown option for move-device: $1"
                        return 1
                        ;;
                esac
            done
            
            move_device "$device_id" "$target_mdm_id" "$confirm"
            ;;
            
        list-mdm-servers)
            local format="table"
            
            while [[ $# -gt 0 ]]; do
                case $1 in
                    --format)
                        format="$2"
                        shift 2
                        ;;
                    --debug)
                        DEBUG=1
                        log_debug "Debug mode enabled"
                        shift
                        ;;
                    *)
                        print_error "Unknown option for list-mdm-servers: $1"
                        return 1
                        ;;
                esac
            done
            
            list_mdm_servers "$format"
            ;;
            
        validate-credentials)
            # Parse any remaining options for validate-credentials
            while [[ $# -gt 0 ]]; do
                case $1 in
                    --debug)
                        DEBUG=1
                        log_debug "Debug mode enabled"
                        shift
                        ;;
                    *)
                        print_error "Unknown option for validate-credentials: $1"
                        return 1
                        ;;
                esac
            done
            
            validate_credentials
            ;;
            
        *)
            print_error "Unknown command: $command"
            usage
            return 1
            ;;
    esac
}

# ============================================================================
# SCRIPT EXECUTION
# ============================================================================

# Only run main if script is executed directly (not sourced)
# In ZSH, check if script is being run directly vs sourced
if [[ "${ZSH_EVAL_CONTEXT:-}" != *:file* ]]; then
    main "$@"
fi