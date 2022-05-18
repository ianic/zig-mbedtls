#!/bin/bash -e

# Errors code generator
# run it like:
# $ ./errors.sh ./zig-cache/o/aaa396bc6232c78f0a7864ae7e4193c5/cimport.zig
# where cimport.zig location is read from zig build when 'verbose_cimport = true;' is set

source=$1

# array of c constats:
c_names=($( grep MBEDTLS_ERR_ $source | cut -d " " -f 3  ))

# convert c names to zig names
zig_names=()
for str in ${c_names[@]}; do
  parts=(`echo $str | tr '_' ' '`) # split on _
  name=""
  # CamelCase parts, except prefix
  for p in ${parts[@]:2}; do
       pp=${p:0:1}"$(tr '[:upper:]' '[:lower:]' <<< ${p:1})"
       name=$name${pp}
  done
  zig_names+=($name)
done

# generate code
echo ""
echo "pub const Error = error{"
echo "    Unknown,"
    for i in "${!c_names[@]}"; do
      c=${c_names[$i]}
      z=${zig_names[$i]}
      echo "    $z,"
    done
echo "};"

echo "pub fn checkError(rc: c_int) Error!void{"
echo "return switch (rc) {"
echo "    0 => {},"
for i in "${!c_names[@]}"; do
  c=${c_names[$i]}
  z=${zig_names[$i]}
  echo "    c.$c => return Error.$z,"
done
echo "    else => Error.Unknown,"
echo "};"
echo "}"
