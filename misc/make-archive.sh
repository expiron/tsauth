#!/bin/sh
authEndpoint=http://auth.tsinghua.edu.cn
usrgEndpoint=http://usereg.tsinghua.edu.cn

# create temp dir
mkdir -p tmp
rm -rf tmp/*

# download essential files
curl -fsSL ${authEndpoint}/srun_portal_pc.php -o tmp/01-auth-srun_portal_pc.php
curl -fsSL ${authEndpoint}/js/hashes.min.js -o tmp/02-auth-hashes.min.js
curl -fsSL ${authEndpoint}/js/portal.main.min.js -o tmp/03-auth-portal.main.min.js
curl -fsSL ${authEndpoint}/script/md5.js -o tmp/04-auth-md5.js

curl -fsSL ${usrgEndpoint}/login.php -o tmp/05-usrg-login.php
curl -fsSL ${usrgEndpoint}/ip_login_import.php -o tmp/06-usrg-ip_login_import.php
curl -fsSL ${usrgEndpoint}/js/portal.main.min.js -o tmp/07-usrg-portal.main.min.js

# file preprocess
enca -L chinese -gx utf-8 tmp/*
sed -i 's/\r//g' tmp/*
sed -i 's/\t/    /g' tmp/*
sed -i 's/\( \)*$//g' tmp/*

mktitle() {
  title=$1
  output=$2
  len=${#title}
  left=$(echo "(80 - $len) / 2 + 1" | bc)
  right=$(echo "82 - $len - $left" | bc)
  echo "\n\n$(seq -s '#' 101 | sed -e 's/[0-9]*//g')" >> $output
  echo -n $(seq -s '#' $left | sed -e 's/[0-9]*//g') >> $output
  echo -n "$(seq -s ' ' 11 | sed -e 's/[0-9]*//g')" >> $output
  echo -n $title >> $output
  echo -n "$(seq -s ' ' 11 | sed -e 's/[0-9]*//g')" >> $output
  echo $(seq -s '#' $right | sed -e 's/[0-9]*//g') >> $output
  echo "$(seq -s '#' 101 | sed -e 's/[0-9]*//g')\n\n" >> $output
}

temp=$(mktemp XXXXXXXX)

# generate sha256sums
mktitle "SHA256SUMS" $temp
cd tmp && sha256sum * >> ../$temp && cd ..

# concat files
for file in $(ls tmp)
do
    mktitle $file $temp
    cat tmp/$file >> $temp
    unlink tmp/$file
done

# generate archive
cat -s $temp | tee $( cd "$(dirname "$0")" && pwd )/archive > /dev/null

# remove temp files and dirs
unlink $temp
rmdir tmp
