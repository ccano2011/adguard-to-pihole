# adguard-to-pihole
Converts Adguard DNS blocklists to pihole

## Key Features:

- Converts AdGuard filter syntax to Pi-hole compatible format
- Handles different AdGuard rule types (domain blocking, whitelists)
- Extracts domains from both AdGuard default lists and your custom rules
- Allows for a list of URLs from a file to generate subsequent blacklists
- Generates Pi-hole import commands automatically
- Preserves whitelist entries

## How to Use:

- Run the script: `./adguard-to-pihole.sh`
- Follow the menu options:

    - Option 1: Process the default AdGuard DNS filter
    - Option 2: Process a custom AdGuard list URL
    - Option 3: Extract domains from an AdGuard backup file
    - Option 4: Process all common AdGuard filter lists
    - Option 5: Process multiple URLs from a file
    - Option 6: Generate Pi-hole import commands
    - Option 7: Exit

The script creates a directory called pihole_lists with your converted lists and a helper script to import them to Pi-hole.

## After Conversion:

- Copy the generated files to your Pi-hole server
- Run the generated import script (after editing paths as needed)