# Apple Business Manager API Tool

🍎 A comprehensive ZSH script for automating Apple Business Manager device operations via the official REST API.

[![Shell](https://img.shields.io/badge/shell-zsh-green.svg)](https://www.zsh.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![macOS](https://img.shields.io/badge/platform-macOS-lightgrey.svg)](https://www.apple.com/macos/)
[![Jamf](https://img.shields.io/badge/jamf-compatible-orange.svg)](https://www.jamf.com/)

## Overview

This tool provides enterprise-grade automation for Apple Business Manager operations, enabling IT administrators to manage device inventories, MDM assignments, and asset lifecycle through a secure, scriptable interface. Perfect for large-scale macOS deployments and integration with existing automation workflows.

## Features

### 🔧 Core Operations
- **Device Inventory**: List all organisational devices with filtering and pagination
- **Device Details**: Retrieve comprehensive device information and status
- **Asset Management**: Remove devices from Apple Business Manager
- **MDM Transfers**: Move devices between Mobile Device Management servers
- **Server Discovery**: List and identify all registered MDM servers

### 🛡️ Enterprise Security
- Secure OAuth 2.0 authentication with JWT Client Assertions
- No hardcoded credentials or API keys
- Environment variable and Jamf parameter support
- Comprehensive audit logging with timestamps
- Rate limiting awareness (100 requests/second)

### 🚀 Deployment Flexibility
- **Standalone execution**: Run directly from command line
- **Jamf integration**: Execute via Jamf Pro policies with parameter passing
- **Utility library**: Source as module in other shell scripts
- **CI/CD compatible**: Perfect for automation pipelines

### 📊 Output Formats
- **Table format**: Human-readable tabular output
- **JSON format**: Machine-parsable structured data
- **Colour-coded**: Visual status indicators and error highlighting
- **Comprehensive logging**: Detailed execution logs for troubleshooting

## Dependencies

### Required Tools
- **curl**: HTTP client for API requests
- **jq**: JSON processor for parsing API responses  
- **openssl**: Cryptographic operations for JWT signing
- **zsh**: Z shell (standard on macOS)

### macOS Compatibility
- macOS 10.15+ (all dependencies included by default)
- Works with both Intel and Apple Silicon Macs
- Compatible with System Integrity Protection (SIP)

### Installation
```bash
# Install via Homebrew (if jq not present)
brew install jq

# Clone repository
git clone https://github.com/yourusername/abm-api-tool.git
cd abm-api-tool

# Make executable
chmod +x abm-api-tool.sh
```

## Security Model

### Authentication Flow
1. **JWT Generation**: Creates signed JSON Web Token using ES256 algorithm
2. **OAuth Exchange**: Trades JWT for short-lived access token
3. **API Requests**: Uses Bearer token authentication for all operations
4. **Token Lifecycle**: Automatic token refresh (1-hour expiry)

### Credential Protection
```bash
# Environment Variables (Recommended)
export ABM_CLIENT_ID="BUSINESSAPI.your-client-id"
export ABM_PRIVATE_KEY_PATH="/secure/path/to/private-key.pem"
export ABM_KEY_ID="your-key-identifier"

# Jamf Parameters (For Policies)
# Parameter 4: Client ID
# Parameter 5: Private Key Path  
# Parameter 6: Key ID
```

### Security Best Practices
- Store private keys in secure locations (`/etc/ssl/private/` or similar)
- Use restrictive file permissions (600) on private key files
- Rotate API credentials regularly
- Monitor access logs for unauthorised usage
- Use dedicated service accounts in Apple Business Manager

## Configuration

### Apple Business Manager Setup
1. Sign in to Apple Business Manager as Administrator
2. Navigate to **Settings > API**
3. Click **Create New API Account**
4. Download the private key (`.pem` file)
5. Note the Client ID and Key ID for configuration

### Script Configuration
The script automatically detects credential sources in this priority order:
1. Jamf policy parameters (`$4`, `$5`, `$6`)
2. Environment variables
3. Interactive prompts (if available)

## Usage Examples

### Basic Operations
```bash
# List all devices in table format
./abm-api-tool.sh list-devices

# List devices with filtering and JSON output
./abm-api-tool.sh list-devices --format json --filter active --limit 50

# Get detailed device information
./abm-api-tool.sh device-details "ABC123DEF456GHI"

# List all MDM servers
./abm-api-tool.sh list-mdm-servers --format table
```

### Device Management
```bash
# Move device to different MDM server (with confirmation)
./abm-api-tool.sh move-device "ABC123DEF456GHI" "new-mdm-server-id"

# Move device without confirmation prompt
./abm-api-tool.sh move-device "ABC123DEF456GHI" "new-mdm-server-id" --confirm

# Remove device from Apple Business Manager
./abm-api-tool.sh delete-device "ABC123DEF456GHI"
```

### Validation and Debugging
```bash
# Test API credentials and connectivity
./abm-api-tool.sh validate-credentials

# Enable debug logging
./abm-api-tool.sh list-devices --debug

# View help information
./abm-api-tool.sh --help
```

## Jamf Pro Integration

### Policy Configuration
1. Create new policy in Jamf Pro
2. Add **Files and Processes** payload
3. Configure script execution:
   ```bash
   /path/to/abm-api-tool.sh list-devices --format json
   ```

### Parameter Mapping
| Jamf Parameter | Description | Example |
|----------------|-------------|---------|
| `$4` | ABM Client ID | `BUSINESSAPI.12345678-1234-1234-1234-123456789abc` |
| `$5` | Private Key Path | `/Library/Application Support/JAMF/keys/abm-private.pem` |
| `$6` | ABM Key ID | `ABCDEF123456` |

### Example Jamf Script
```bash
#!/bin/zsh
# Jamf Policy Script Example

CLIENT_ID="$4"
PRIVATE_KEY_PATH="$5" 
KEY_ID="$6"

# Execute ABM API tool with Jamf parameters
/usr/local/bin/abm-api-tool.sh list-devices --format json > /tmp/device-inventory.json

# Process results
device_count=$(jq '.data | length' /tmp/device-inventory.json)
echo "Total devices managed: $device_count"
```

## API Reference

### Available Commands

| Command | Description | Options |
|---------|-------------|---------|
| `list-devices` | List organisational devices | `--format`, `--filter`, `--limit` |
| `device-details` | Get device information | `--format` |
| `delete-device` | Remove device from ABM | `--confirm` |
| `move-device` | Transfer to different MDM | `--confirm` |
| `list-mdm-servers` | List MDM servers | `--format` |
| `validate-credentials` | Test API connectivity | None |

### Global Options

| Option | Description | Values |
|--------|-------------|--------|
| `--format` | Output format | `json`, `table` |
| `--filter` | Device status filter | `active`, `inactive`, `all` |
| `--limit` | Result pagination | Integer (1-1000) |
| `--confirm` | Skip confirmation prompts | Flag |
| `--debug` | Enable debug logging | Flag |
| `--help` | Display usage information | Flag |

## Logging and Monitoring

### Log Locations
- **Execution logs**: `/tmp/abm-api-tool.log`
- **Debug output**: Console (when `--debug` enabled)
- **Audit trail**: Timestamped entries with request details

### Log Levels
- **INFO**: General operational information
- **WARN**: Non-critical warnings and advisories  
- **ERROR**: Error conditions and failures
- **DEBUG**: Detailed troubleshooting information

### Sample Log Output
```
2024-01-15 10:30:45 [INFO] Loading API credentials from environment variables
2024-01-15 10:30:45 [INFO] Credentials loaded successfully
2024-01-15 10:30:46 [DEBUG] Generating JWT for authentication
2024-01-15 10:30:46 [DEBUG] Requesting OAuth access token
2024-01-15 10:30:47 [INFO] Listing devices (format: table, filter: all, limit: 100)
2024-01-15 10:30:47 [DEBUG] Making API request: GET /orgDevices?limit=100
```

## Troubleshooting

### Common Issues

#### Authentication Failures
```bash
# Error: "Authentication failed (401)"
# Solution: Verify credentials and key file permissions
ls -la /path/to/private-key.pem
chmod 600 /path/to/private-key.pem

# Test credentials
./abm-api-tool.sh validate-credentials --debug
```

#### Missing Dependencies
```bash
# Error: "Missing required dependencies: jq"
# Solution: Install missing tools
brew install jq

# Verify installation
which jq curl openssl
```

#### Rate Limiting
```bash
# Error: "Rate limit exceeded (429)"
# Solution: Implement delays between requests
sleep 1  # Add delays in loops
```

#### Private Key Issues
```bash
# Error: "Cannot read private key file"
# Check file exists and is readable
test -r "$ABM_PRIVATE_KEY_PATH" && echo "Readable" || echo "Not readable"

# Verify key format
openssl ec -in "$ABM_PRIVATE_KEY_PATH" -text -noout
```

### Debug Mode
Enable comprehensive debugging for troubleshooting:
```bash
DEBUG=1 ./abm-api-tool.sh validate-credentials
```

## Performance Considerations

### API Rate Limits
- Apple Business Manager API: **100 requests/second**
- Token lifetime: **1 hour**
- Pagination: **100-1000 items per request**

### Optimisation Tips
- Use appropriate `--limit` values for large inventories
- Cache access tokens for multiple operations
- Implement exponential backoff for rate limit handling
- Use JSON format for programmatic processing

### Bulk Operations
```bash
# Process devices in batches
./abm-api-tool.sh list-devices --limit 500 --format json | \
jq -r '.data[].id' | \
while read device_id; do
    ./abm-api-tool.sh device-details "$device_id"
    sleep 0.1  # Rate limiting
done
```

## Contributing

### Development Setup
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Follow shell scripting best practices
4. Test with both environment variables and Jamf parameters
5. Submit pull request with comprehensive description

### Code Standards
- Use `shellcheck` for linting
- Follow existing indentation and naming conventions
- Add appropriate error handling and logging
- Update documentation for new features
- Test on multiple macOS versions

### Testing Checklist
- [ ] Credential validation works
- [ ] All commands execute successfully
- [ ] JSON and table outputs are correct
- [ ] Jamf parameter integration functions
- [ ] Error conditions are handled gracefully
- [ ] Logging provides adequate detail

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- Apple Business Manager API team for comprehensive documentation
- Jamf Pro community for integration insights
- macOS administration community for testing and feedback

## Support

### Documentation
- [Apple Business Manager API Documentation](https://developer.apple.com/documentation/applebusinessmanagerapi)
- [Jamf Pro Administrator Guide](https://docs.jamf.com/)

### Community
- Create GitHub issues for bugs and feature requests
- Join discussions in the repository's discussion section
- Contribute improvements via pull requests

---

**⚠️ Important**: This tool requires appropriate Apple Business Manager Administrator permissions and should only be used in accordance with your organisation's security policies and Apple's terms of service.
