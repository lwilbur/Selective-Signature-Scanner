#!/usr/bin/python3
import os
from subprocess import run

##### HEAD/TAIL LENGTH CALCULATION #####
# Construct list of head-tail lengths
perc90 = 500
perc100 = 855
multipliers = [1 + (0.25*i) for i in range(1, 37)]  # 1.25,1.5,...,10.0
lens = [perc90, perc100]
lens += [(int)(i*perc100) for i in multipliers]


##### DIRECTORY CREATION #####
# Construct directory names with naming scheme: mw_uzip_1pt25x100_perc
dirs = ["mw_uzip_90_perc", "mw_uzip_100_perc"]
dirs += [f"mw_uzip_{m}x100_perc".replace(".", "pt") for m in multipliers]

# Make directories
parent_dir = "mw_uzip_head_tail"
run(["mkdir", parent_dir])
for dir_name in dirs:
    run(["mkdir", f"{parent_dir}/{dir_name}"])


##### HEAD&TAIL FILE CREATION #####
# Construct tags to append to filenames of head&tail
filename_appends = ["_90_perc", "_100_perc"]
filename_appends += [f"_{m}".replace(".", "pt") for m in multipliers]

# For each malware sample, create a head+tail file of each length
# NOTE: "-q" flag does not exist on Mac OS implementation -- use Linux
samples = os.listdir("./malware_unzipped")
for filename in samples:          # each sample
    for i in range(len(lens)):    # each length head/tail
        out_name = f"{parent_dir}/{dirs[i]}/{filename}{filename_appends[i]}"
        out_file = open(out_name, "w+")
        run(["head", "-q", "--bytes", str(lens[i]), f"malware_unzipped/{filename}"], 
            stdout=out_file)
        run(["tail", "-q", "--bytes", str(lens[i]), f"malware_unzipped/{filename}"],
            stdout=out_file)
        out_file.close()

