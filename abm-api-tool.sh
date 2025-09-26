#!/bin/zsh

# Apple Business Manager API Tool
# A comprehensive zsh script for interfacing with the Apple Business Manager API
# 
# SECURITY: API credentials must be provided via environment variables or Jamf parameters
# USAGE: Can be run standalone, from Jamf policies, or as a utility script
#
# Author: David 'Bing' Crosby
# Version: 1.0
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
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $*" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { 
    [[ "${DEBUG:-}" == "1" ]] && log "DEBUG" "$@" || true
}

print_success() { printf "${GREEN}✓ %s${NC}\n" "$*"; }
print_error() { printf "${RED}✗ %s${NC}\n" "$*"; }
print_warning() { printf "${YELLOW}⚠ %s${NC}\n" "$*"; }
print_info() { printf "${BLUE}ℹ %s${NC}\n" "$*"; }

cleanup() {
    local exit_code=$?
    log_info "Script execution completed with exit code: $exit_code"
    exit $exit_code
}
trap cleanup EXIT

usage() {
    cat << EOF
${GREEN}Apple Business Manager API Tool${NC}

${BLUE}USAGE:${NC}
    $SCRIPT_NAME <command> [options]

${BLUE}COMMANDS:${NC}
    list-devices [--format json|table] [--filter active|inactive|all] [--limit N]
        List all organisational devices
        
    device-details <device-id> [--format json|table]
        Get detailed information for a specific device
        
    delete-device <device-id> [--confirm]
        Remove a device from Apple Business Manager
        
    move-device <device-id> <target-mdm-server-id> [--confirm]
        Move a device from one MDM to another
        
    list-mdm-servers [--format json|table]
        List all registered MDM servers
        
    validate-credentials
        Test API connectivity and authentication

${BLUE}OPTIONS:${NC}
    --format json|table     Output format (default: table)
    --filter active|inactive|all    Filter devices by status (default: all)
    --limit N               Limit number of results (default: 100)
    --confirm               Skip confirmation prompts
    --debug                 Enable debug logging
    --help                  Show this help message

${BLUE}ENVIRONMENT VARIABLES:${NC}
    ABM_CLIENT_ID           Apple Business Manager API Client ID
    ABM_PRIVATE_KEY_PATH    Path to the private key (.pem file)
    ABM_KEY_ID              Key ID from Apple Business Manager

${BLUE}JAMF PARAMETERS:${NC}
    \$4 = ABM_CLIENT_ID
    \$5 = ABM_PRIVATE_KEY_PATH  
    \$6 = ABM_KEY_ID

${BLUE}EXAMPLES:${NC}
    # List all devices in table format
    $SCRIPT_NAME list-devices --format table
    
    # Get details for a specific device
    $SCRIPT_NAME device-details "ABC123DEF456"
    
    # Move device to different MDM server
    $SCRIPT_NAME move-device "ABC123DEF456" "mdm-server-123" --confirm
    
    # Delete a device (with confirmation)
    $SCRIPT_NAME delete-device "ABC123DEF456"

EOF
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
    
    # JWT Header
    local header=$(printf '{"alg":"ES256","kid":"%s","typ":"JWT"}' "$ABM_KEY_ID" | base64 | tr -d '=\n' | tr '+/' '-_')
    
    # JWT Payload
    local payload=$(printf '{"sub":"BUSINESSAPI.%s","aud":"%s","iat":%d,"exp":%d,"jti":"%s","iss":"BUSINESSAPI.%s"}' \
        "$ABM_CLIENT_ID" "$OAUTH_TOKEN_URL" "$current_time" "$expiry_time" "$jti" "$ABM_CLIENT_ID" | \
        base64 | tr -d '=\n' | tr '+/' '-_')
    
    # Sign the JWT
    local unsigned_token="${header}.${payload}"
    local signature=$(printf '%s' "$unsigned_token" | \
        openssl dgst -sha256 -sign "$ABM_PRIVATE_KEY_PATH" | \
        base64 | tr -d '=\n' | tr '+/' '-_')
    
    printf '%s.%s.%s' "$header" "$payload" "$signature"
}

get_access_token() {
    log_debug "Requesting OAuth access token"
    
    local jwt
    jwt=$(generate_jwt) || {
        log_error "Failed to generate JWT"
        return 1
    }
    
    local response
    response=$(curl -s -X POST "$OAUTH_TOKEN_URL" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        -d "client_id=BUSINESSAPI.${ABM_CLIENT_ID}" \
        -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
        -d "client_assertion=${jwt}" \
        -d "scope=business.api") || {
        log_error "Failed to request access token"
        return 1
    }
    
    # Check if response contains an error
    if echo "$response" | jq -e '.error' >/dev/null 2>&1; then
        local error_msg
        error_msg=$(echo "$response" | jq -r '.error_description // .error')
        log_error "OAuth error: $error_msg"
        return 1
    fi
    
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
    
    print_info "Testing JWT generation..."
    local jwt
    jwt=$(generate_jwt) || {
        print_error "JWT generation failed"
        return 1
    }
    print_success "JWT generated successfully"
    
    print_info "Testing OAuth token retrieval..."
    local access_token
    access_token=$(get_access_token) || {
        print_error "OAuth token retrieval failed"
        return 1
    }
    print_success "Access token retrieved successfully"
    
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
                    *)
                        print_error "Unknown option for list-mdm-servers: $1"
                        return 1
                        ;;
                esac
            done
            
            list_mdm_servers "$format"
            ;;
            
        validate-credentials)
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
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi