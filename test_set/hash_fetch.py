#!/usr/bin/env python3
import os
import subprocess

# wget --post-data "query=get_file&sha256_hash=094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d" https://mb-api.abuse.ch/api/v1/

# List of Yara rules to query and API address
yara_rules = os.listdir("./YARA_rules")
print(yara_rules)
api_site = "https://yaraify-api.abuse.ch/api/v1/"

def main():
    # Create folder to hold all the rule folders
    malware_file = "malware_samples"
    subprocess.run(["mkdir", malware_file])

    # Handle each rule
    for rule_filename in yara_rules:
        # Cut off .yar from filename to get just the rule's name
        rule = rule_filename[:-(len(".yar"))]
        print(rule)

        # Open list of malware hashes matched by YARA rule (previously fetched)
        hashes_file = open(f"rule_hashes/{rule}_hashes.txt")
        hashes = hashes_file.read().splitlines()
        hashes = hashes[1:]  # cut off header line
        hashes_file.close()

        # Fetch the malware matching the 50 most recent hashes
        i = 0
        for table_line in hashes[:50]:
            # 3rd entry in " " delimited line is the hash
            mal_hash = table_line.split()[2]
            data = '{ "query": "get_unpacked", "sha256_hash": "' + mal_hash + '" }' 

            i += 1
            print(f"\t{i=}")
            print(f"\t\t{mal_hash=}")
            print(f"\t\t{data=}")

            """
            output = open(f"{malware_file}/{rule}_{mal_hash}", 'w')
            shell_call = ['curl', '-X', 'POST', '-d', data, api_site]
            subprocess.run(shell_call, stdout=output)
            output.close()
            """

if __name__== "__main__":
    main()

