#!/bin/bash

# AdGuard to Pi-hole blocklist conversion script
# This script takes AdGuard DNS filter lists and converts them to Pi-hole compatible format

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Display banner
echo -e "${GREEN}========================================================"
echo -e "       AdGuard to Pi-hole Blocklist Converter"
echo -e "========================================================${NC}\n"

# Check if required tools are installed
for cmd in curl grep sed awk sort uniq; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "${RED}Error: $cmd is required but not installed.${NC}"
        exit 1
    fi
done

# Create temporary and output directories
TEMP_DIR="$(mktemp -d)"
OUTPUT_DIR="./pihole_lists"
mkdir -p "$OUTPUT_DIR"

# Function to process AdGuard filter list
process_adguard_list() {
    local url="$1"
    local output_file="$2"
    local list_name="$3"
    
    echo -e "${YELLOW}Processing $list_name...${NC}"
    
    # Download the list
    echo "Downloading from $url..."
    if ! curl -s "$url" -o "$TEMP_DIR/adguard_raw.txt"; then
        echo -e "${RED}Failed to download the list.${NC}"
        return 1
    fi
    
    # Extract domains from different AdGuard rule types
    echo "Extracting domains..."
    
    # Process the file line by line to handle different rule formats
    cat "$TEMP_DIR/adguard_raw.txt" | while read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*($|!) ]] && continue
        
        # Handle ||domain^ format (most common)
        if [[ "$line" =~ ^\|\|([a-zA-Z0-9.-]+)\^ ]]; then
            echo "${BASH_REMATCH[1]}" >> "$TEMP_DIR/domains.txt"
        
        # Handle ||domain^$important format
        elif [[ "$line" =~ ^\|\|([a-zA-Z0-9.-]+)\^\$important ]]; then
            echo "${BASH_REMATCH[1]}" >> "$TEMP_DIR/domains.txt"
            
        # Handle domain.com format (without any special chars)
        elif [[ "$line" =~ ^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$ ]]; then
            echo "${BASH_REMATCH[1]}" >> "$TEMP_DIR/domains.txt"
            
        # Handle @@||domain^ (whitelist) format
        elif [[ "$line" =~ ^@@\|\|([a-zA-Z0-9.-]+)\^ ]]; then
            echo "${BASH_REMATCH[1]}" >> "$TEMP_DIR/whitelist.txt"
            
        # Handle hosts file format (0.0.0.0 domain.com or 127.0.0.1 domain.com)
        elif [[ "$line" =~ ^(0\.0\.0\.0|127\.0\.0\.1)[[:space:]]+([a-zA-Z0-9.-]+) ]]; then
            echo "${BASH_REMATCH[2]}" >> "$TEMP_DIR/domains.txt"
            
        # Handle IP address format without domain (just extract the domain)
        elif [[ "$line" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[[:space:]]+([a-zA-Z0-9.-]+) ]]; then
            echo "${BASH_REMATCH[1]}" >> "$TEMP_DIR/domains.txt"
        fi
    done
    
    # Sort, remove duplicates and save to output file
    if [ -f "$TEMP_DIR/domains.txt" ]; then
        sort "$TEMP_DIR/domains.txt" | uniq > "$output_file"
        echo -e "${GREEN}Extracted $(wc -l < "$output_file") domains to $output_file${NC}"
    else
        echo -e "${RED}No domains were extracted${NC}"
    fi
    
    # Process whitelist if any
    if [ -f "$TEMP_DIR/whitelist.txt" ]; then
        sort "$TEMP_DIR/whitelist.txt" | uniq > "${output_file%.txt}_whitelist.txt"
        echo -e "${GREEN}Extracted $(wc -l < "${output_file%.txt}_whitelist.txt") whitelist domains${NC}"
    fi
    
    # Clean up temporary files
    rm -f "$TEMP_DIR/domains.txt" "$TEMP_DIR/whitelist.txt" "$TEMP_DIR/adguard_raw.txt"
}

# Function to process local AdGuard backup file
process_adguard_yaml() {
    local backup_file="$1"
    
    echo -e "${YELLOW}Processing AdGuard YAML config file...${NC}"
    
    if [ ! -f "$backup_file" ]; then
        echo -e "${RED}Config file not found: $backup_file${NC}"
        return 1
    fi
    
    # Create a URL list file
    url_list_file="$OUTPUT_DIR/adguard_filter_urls.txt"
    echo "# AdGuard filter URLs extracted from config file" > "$url_list_file"
    echo "# Generated on $(date)" >> "$url_list_file"
    echo "" >> "$url_list_file"
    
    # Extract filter URLs from YAML format
    echo "Extracting filter URLs from YAML config..."
    
    # This pattern matches the url: line within filter sections in YAML
    grep -A 3 'enabled: true' "$backup_file" | grep 'url:' | sed 's/.*url: //g' | while read -r url; do
        # Extract name as well if possible
        name=$(grep -A 2 "url: $url" "$backup_file" | grep 'name:' | head -1 | sed 's/.*name: //g' | tr ' ' '_')
        
        if [ -n "$name" ]; then
            echo "$url#$name" >> "$url_list_file"
        else
            echo "$url" >> "$url_list_file"
        fi
    done
    
    # Count how many URLs we extracted
    url_count=$(grep -v '^#' "$url_list_file" | grep -v '^$' | wc -l)
    
    if [ "$url_count" -eq 0 ]; then
        echo -e "${RED}No filter URLs found in the config file.${NC}"
        return 1
    else
        echo -e "${GREEN}Extracted $url_count filter URLs to $url_list_file${NC}"
    fi
    
    # Now extract and process user rules (custom filtering rules)
    echo "Extracting user defined rules..."
    
    # Extract user rules from YAML
    user_rules_start=$(grep -n "user_rules:" "$backup_file" | cut -d':' -f1)
    
    if [ -n "$user_rules_start" ]; then
        # Determine where user_rules section ends
        next_section=$(tail -n +$((user_rules_start+1)) "$backup_file" | grep -n "^[a-z]" | head -1 | cut -d':' -f1)
        
        if [ -n "$next_section" ]; then
            # Extract lines between user_rules: and the next section
            tail -n +$((user_rules_start+1)) "$backup_file" | head -n $((next_section-1)) > "$TEMP_DIR/user_rules.txt"
        else
            # If there's no next section, extract to the end of file
            tail -n +$((user_rules_start+1)) "$backup_file" > "$TEMP_DIR/user_rules.txt"
        fi
        
        # Process the user rules to extract domain patterns
        cat "$TEMP_DIR/user_rules.txt" | grep -o "||[^'^\"]*\^" | sed 's/||//;s/\^//' > "$TEMP_DIR/custom_domains.txt"
        
        # Sort, remove duplicates and save user rules to output file
        if [ -f "$TEMP_DIR/custom_domains.txt" ] && [ -s "$TEMP_DIR/custom_domains.txt" ]; then
            sort "$TEMP_DIR/custom_domains.txt" | uniq > "$OUTPUT_DIR/adguard_custom_rules.txt"
            echo -e "${GREEN}Extracted $(wc -l < "$OUTPUT_DIR/adguard_custom_rules.txt") custom domains to adguard_custom_rules.txt${NC}"
        else
            echo -e "${YELLOW}No custom domains were extracted from user rules${NC}"
        fi
    fi
    
    # Now process each URL from our extracted list
    echo -e "${YELLOW}Processing extracted filter URLs...${NC}"
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        
        # Extract URL and optional name
        if [[ "$line" =~ ([^#]+)#(.+) ]]; then
            url="${BASH_REMATCH[1]}"
            name="${BASH_REMATCH[2]}"
        else
            url="$line"
            # Generate name from URL
            name=$(echo "$url" | sed 's|.*/||' | sed 's|\.[^.]*$||')
        fi
        
        # Clean up URL and name
        url=$(echo "$url" | tr -d '\r' | xargs)
        name=$(echo "$name" | tr -d '\r' | xargs | tr ' ' '_')
        
        echo -e "${YELLOW}Processing $url as $name${NC}"
        process_adguard_list "$url" "$OUTPUT_DIR/${name}.txt" "$name"
        
    done < "$url_list_file"
    
    # Clean up
    rm -f "$TEMP_DIR/user_rules.txt" "$TEMP_DIR/custom_domains.txt"
    
    echo -e "${GREEN}Config processing complete. Check $OUTPUT_DIR for all extracted lists.${NC}"
}

# Function to generate Pi-hole import command
generate_pihole_command() {
    echo -e "${YELLOW}Generating Pi-hole import commands...${NC}"
    
    local command_file="$OUTPUT_DIR/pihole_import_commands.sh"
    
    echo "#!/bin/bash" > "$command_file"
    echo "" >> "$command_file"
    echo "# Commands to import converted lists to Pi-hole" >> "$command_file"
    echo "# Run this script on your Pi-hole server" >> "$command_file"
    echo "" >> "$command_file"
    
    # Add commands for each list file
    for file in "$OUTPUT_DIR"/*.txt; do
        if [[ "$file" == *"whitelist"* ]]; then
            # Whitelist command using current Pi-hole syntax (allow/allowlist)
            echo "# Import whitelist from $(basename "$file")" >> "$command_file"
            echo "echo \"Importing whitelist: $(basename "$file")\"" >> "$command_file"
            
            # Method using allowlist command
            echo "cat \"$(basename "$file")\" | while read domain; do" >> "$command_file"
            echo "    [[ -z \"\$domain\" || \"\$domain\" =~ ^# ]] && continue  # Skip empty lines and comments" >> "$command_file"
            echo "    echo \"Adding \$domain to allowlist\"" >> "$command_file"
            echo "    pihole allowlist \"\$domain\" \"Imported from AdGuard\"" >> "$command_file"
            echo "done" >> "$command_file"
            echo "" >> "$command_file"
            
            # Alternative method - direct file modification
            echo "# Alternative method: Direct whitelist file modification" >> "$command_file"
            echo "echo \"Adding domains to whitelist.txt...\"" >> "$command_file"
            echo "cat \"$(basename "$file")\" | grep -v \"^#\" | grep -v \"^$\" >> /etc/pihole/whitelist.txt" >> "$command_file"
            echo "echo \"Whitelist entries added. Restarting Pi-hole services...\"" >> "$command_file"
            echo "pihole restartdns" >> "$command_file"
            echo "" >> "$command_file"
        else
            # Blocklist command - use denylist for Pi-hole current version
            list_name=$(basename "$file" .txt)
            echo "# Import blocklist: $list_name" >> "$command_file"
            echo "echo \"Importing blocklist: $list_name\"" >> "$command_file"
            
            # Method using denylist command
            echo "echo \"Adding domains from $list_name to denylist...\"" >> "$command_file"
            echo "cat \"$(basename "$file")\" | while read domain; do" >> "$command_file"
            echo "    [[ -z \"\$domain\" || \"\$domain\" =~ ^# ]] && continue  # Skip empty lines and comments" >> "$command_file"
            echo "    echo \"Adding \$domain to denylist\"" >> "$command_file" 
            echo "    pihole denylist \"\$domain\" \"Imported from AdGuard - $list_name\"" >> "$command_file"
            echo "done" >> "$command_file"
            echo "" >> "$command_file"
            
            # Alternative method - adding to adlists for gravity
            echo "# Alternative method: Adding as an adlist" >> "$command_file"
            echo "echo \"Creating a local adlist file for $list_name...\"" >> "$command_file"
            echo "# First create a local file with the domains in adlist format" >> "$command_file"
            echo "mkdir -p /etc/pihole/adlists/" >> "$command_file"
            echo "cat \"$(basename "$file")\" | grep -v \"^#\" | grep -v \"^$\" > /etc/pihole/adlists/$list_name.list" >> "$command_file"
            echo "echo \"Update gravity to apply changes\"" >> "$command_file"
            echo "pihole -g" >> "$command_file"
            echo "" >> "$command_file"
        fi
    done
    
    echo "# Update gravity after importing all lists" >> "$command_file"
    echo "pihole -g" >> "$command_file"
    
    chmod +x "$command_file"
    echo -e "${GREEN}Generated Pi-hole import commands in $command_file${NC}"
    echo -e "${YELLOW}Note: You'll need to copy the generated files to your Pi-hole server and edit paths in the import script.${NC}"
}

# Function to process multiple URLs from a file
process_url_file() {
    local url_file="$1"
    
    if [ ! -f "$url_file" ]; then
        echo -e "${RED}File not found: $url_file${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}Processing URLs from $url_file...${NC}"
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        
        # Extract URL and optional name
        if [[ "$line" =~ ([^#]+)#(.+) ]]; then
            url="${BASH_REMATCH[1]}"
            name="${BASH_REMATCH[2]}"
        else
            url="$line"
            # Generate name from URL
            name=$(echo "$url" | sed 's|.*/||' | sed 's|\.[^.]*$||')
        fi
        
        # Clean up URL and name
        url=$(echo "$url" | tr -d '\r' | xargs)
        name=$(echo "$name" | tr -d '\r' | xargs | tr ' ' '_')
        
        echo -e "${YELLOW}Processing $url as $name${NC}"
        process_adguard_list "$url" "$OUTPUT_DIR/${name}.txt" "$name"
        
    done < "$url_file"
}

# Main menu
show_menu() {
    echo -e "${GREEN}Choose an option:${NC}"
    echo "1) Process AdGuard DNS Filter (default list)"
    echo "2) Process AdGuard DNS Filter from custom URL"
    echo "3) Process AdGuard Home YAML config file"
    echo "4) Process all default AdGuard filter lists"
    echo "5) Process multiple URLs from a file"
    echo "6) Generate Pi-hole import commands"
    echo "7) Exit"
    echo -n "Enter your choice [1-7]: "
    read choice
    
    case "$choice" in
        1)
            process_adguard_list "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt" \
                                "$OUTPUT_DIR/adguard_dns_filter.txt" "AdGuard DNS Filter"
            show_menu
            ;;
        2)
            echo -n "Enter AdGuard filter list URL: "
            read -r custom_url
            custom_url=$(echo "$custom_url" | tr -d '\r')
            
            echo -n "Enter output filename: "
            read -r output_name
            output_name=$(echo "$output_name" | tr -d '\r')
            
            if [[ -z "$output_name" ]]; then
                output_name="custom_adguard_filter.txt"
            elif [[ ! "$output_name" =~ \.txt$ ]]; then
                output_name="${output_name}.txt"
            fi
            
            echo "URL: $custom_url"
            echo "Output: $output_name"
            process_adguard_list "$custom_url" "$OUTPUT_DIR/$output_name" "Custom AdGuard Filter"
            show_menu
            ;;
        3)
            echo -n "Enter path to AdGuard Home YAML config file: "
            read -r config_file
            process_adguard_yaml "$config_file"
            show_menu
            ;;
        4)
            # Process multiple default AdGuard lists
            process_adguard_list "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt" \
                                "$OUTPUT_DIR/adguard_dns_filter.txt" "AdGuard DNS Filter"
            
            process_adguard_list "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt" \
                                "$OUTPUT_DIR/adguard_malware_filter.txt" "AdGuard Malware Filter"
                                
            process_adguard_list "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt" \
                                "$OUTPUT_DIR/adguard_social_filter.txt" "AdGuard Social Media Filter"
            
            process_adguard_list "https://adguardteam.github.io/HostlistsRegistry/assets/filter_35.txt" \
                                "$OUTPUT_DIR/adguard_mobile_filter.txt" "AdGuard Mobile Ads Filter"
            
            show_menu
            ;;
        5)
            echo -n "Enter path to file containing AdGuard filter URLs (one URL per line): "
            read -r url_file
            process_url_file "$url_file"
            show_menu
            ;;
        6)
            generate_pihole_command
            show_menu
            ;;
        7)
            echo -e "${GREEN}Thank you for using the AdGuard to Pi-hole converter!${NC}"
            echo -e "${YELLOW}Your converted lists are in the '$OUTPUT_DIR' directory.${NC}"
            rm -rf "$TEMP_DIR"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Please try again.${NC}"
            show_menu
            ;;
    esac
}

# Start the script
show_menu