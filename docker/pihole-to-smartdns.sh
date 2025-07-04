#!/usr/bin/env bash

# Converts a pihole adlist like https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts to
# a smartdns compatible format. Download the respective adlist and save it as pihole.txt in the same folder as this script.
# Run this script and copy the content of the generated smartdns-ads.txt to your smartdns.conf file.

output=''
block_prefix="address /"
block_suffix="/0.0.0.0"

while read p; do

  trimmed_output=$(echo $p| sed 's/^[ \t]*//;s/[ \t]*$//')
  # If line is not a comment and not empty
  if [[ $p != \#* && ! -z $trimmed_output ]]  ; then
      output+=$block_prefix$(echo $trimmed_output | cut -d ' ' -f 2)$block_suffix
  else
      output+=$(echo $trimmed_output)
  fi
  output+='\n'
done <pihole.txt

echo -e $output > smartdns-ads.txt
