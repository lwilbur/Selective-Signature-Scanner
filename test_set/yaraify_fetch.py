#!/usr/bin/env python3
import subprocess

# wget --post-data "query=get_file&sha256_hash=094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d" https://mb-api.abuse.ch/api/v1/

# List of Yara rules to query and API address
yara_rules = [("unpacked_qbot", "a2ad2850-fa12-469f-947a-9dbf79ffcc51")]
api_site = "https://yaraify-api.abuse.ch/api/v1/"

def main():
    # Create folder to hold all the rule folders
    main_folder = "malware_samples"
    subprocess.run(["mkdir", main_folder])

    # Create folder to hold all the .yar files
    rule_folder = "YARA_rules"
    subprocess.run(["mkdir", rule_folder])

    # Handle each rule
    for rule in yara_rules:
        # Pull out parts
        name = rule[0]
        uuid = rule[1]

        # Create a folder for the rule
        dir_path = f"{main_folder}/{name}"
        subprocess.run(["mkdir", dir_path])

        # Fetch the rule itself from YARAify
        data = '{ "query": "get_yara_rule", "uuid": "' + uuid + '" }' 
        output = open(f"{rule_folder}/{name}.yar", 'w')
        shell_call = ['curl', '-X', 'POST', '-d', data, api_site]
        subprocess.run(shell_call, stdout=output)
        output.close()
                        
        # Fetch list of 50 malware hashes matched by YARA rule
        data = '{ "query": "get_yara", "search_term": "' + rule[0] + '" }' 
        output = open(f"{dir_path}/sample_list", 'w')
        shell_call = ['curl', '-X', 'POST', '-d', data, api_site]
        subprocess.run(shell_call, stdout=output)
        output.close()


if __name__== "__main__":
    main()

