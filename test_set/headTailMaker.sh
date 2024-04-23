#!/bin/bash
# NOTE: head -q does not exist on Mac OS -- use linux

# Lengths
len_90_perc=413
len_100_perc=500
len_1pt25x100=625
len_1pt5x100=750
len_1pt75x100=875
len_2x100=1000
len=($len_90_perc\
     $len_100_perc\
     $len_1pt25x100\
     $len_1pt5x100\
     $len_1pt75x100\
     $len_2x100)

# Create directories
dir_90_perc="mw_uzip_90_perc"
dir_100_perc="mw_uzip_100_perc"
dir_1pt25x100_perc="mw_uzip_1pt25x100_perc"
dir_1pt5x100_perc="mw_uzip_1pt5x100_perc"
dir_1pt75x100_perc="mw_uzip_1pt75x100_perc"
dir_2x100_perc="mw_uzip_2x100_perc"
dir=($dir_90_perc\
     $dir_100_perc\
     $dir_1pt25x100_perc\
     $dir_1pt5x100_perc\
     $dir_1pt75x100_perc\
     $dir_2x100_perc)

for d in ${dir[@]}; do
    mkdir ${d}
done

# Create labels to append to filenames once head/tail removed
append=("_90_perc" "_100_perc" "_1pt25" "_1pt5" "_1pt75" "_2")

# For each file, create a head+tail file of each length
for filename in malware_unzipped/*; do
    basename="${filename##*/}"

    # Loop over indices in dir, creating each
    for i in ${!dir[@]}; do
        outfile="${dir[$i]}/${basename}${append[$i]}"
        head -q --bytes "${len[$i]}" $filename > $outfile
        tail -q --bytes "${len[$i]}" $filename >> $outfile
    done
done

