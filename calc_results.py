#!/usr/bin/python3
import os
from subprocess import run

# Construct directory names with naming scheme: mw_uzip_1pt25x100_perc
# NB: same scheme used in head-tail file making, so this covers all
multipliers = [1 + (0.25*i) for i in range(1, 37)]  # 1.25,1.5,...,10.0
dirs = ["mw_uzip_90_perc", "mw_uzip_100_perc"]
dirs += [f"mw_uzip_{m}x100_perc".replace(".", "pt") for m in multipliers]

# Create file to hold results
results_file = open("results", "w+")

# Run on full files
run(["./3S", "test_set/YARA_rules", "test_set/malware_unzipped"],
    stdout=results_file)

# Run on head&tail files
for directory in dirs:
    run(["./3S", "test_set/YARA_rules", f"test_set/mw_uzip_head_tail/{directory}"],
        stdout=results_file)

results_file.close()
