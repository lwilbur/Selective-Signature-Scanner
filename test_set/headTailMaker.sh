#!/bin/bash
# NOTE: head -q does not exist on Mac OS -- use linux

# Lengths
len_90_perc=500
len_100_perc=855
len_1pt25x100=1068
len_1pt5x100=1282
len_1pt75x100=1496
len_2x100=1710
len_2pt25x100=1923
len_2pt5x100=2137
len_2pt75x100=2351
len_3x100=2565
len=($len_90_perc\
     $len_100_perc\
     $len_1pt25x100\
     $len_1pt5x100\
     $len_1pt75x100\
     $len_2x100\
     $len_2pt25x100\
     $len_2pt5x100\
     $len_2pt75x100\
     $len_3x100)

# Create directories
dir_90_perc="mw_uzip_90_perc"
dir_100_perc="mw_uzip_100_perc"
dir_1pt25x100_perc="mw_uzip_1pt25x100_perc"
dir_1pt5x100_perc="mw_uzip_1pt5x100_perc"
dir_1pt75x100_perc="mw_uzip_1pt75x100_perc"
dir_2x100_perc="mw_uzip_2x100_perc"
dir_2pt25x100_perc="mw_uzip_2pt25x100_perc"
dir_2pt5x100_perc="mw_uzip_2pt5x100_perc"
dir_2pt75x100_perc="mw_uzip_2pt75x100_perc"
dir_3x100_perc="mw_uzip_3x100_perc"
dir=($dir_90_perc\
     $dir_100_perc\
     $dir_1pt25x100_perc\
     $dir_1pt5x100_perc\
     $dir_1pt75x100_perc\
     $dir_2x100_perc\
     $dir_2pt25x100_perc\
     $dir_2pt5x100_perc\
     $dir_2pt75x100_perc\
     $dir_3x100_perc)

for d in ${dir[@]}; do
    mkdir ${d}
done

# Create labels to append to filenames once head/tail removed
append=("_90_perc"\
        "_100_perc"\
        "_1pt25"\
        "_1pt5"\
        "_1pt75"\
        "_2"\
        "_2pt25"\
        "_2pt5"\
        "_2pt75"\
        "_3")

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

