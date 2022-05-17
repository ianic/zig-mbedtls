#!/bin/bash -e
#
# grep MBEDTLS_ERR_ /Users/ianic/code/zig/ninja/zig-mbedtls/zig-cache/o/e4954ff27820eeb23e89a87d2dbf4052/cimport.zig | \
#      cut -d " " -f 3 | \
#      gsed -E 's/MBEDTLS_ERR_([A-Z])/\1/g' | \
#      gsed 's/[A-Z]/\L&/g' | \
#      gsed -r 's/(^|_)([a-z])/\U\2/g'


source="/Users/ianic/code/zig/ninja/zig-mbedtls/zig-cache/o/e4954ff27820eeb23e89a87d2dbf4052/cimport.zig"
c_names=($( grep MBEDTLS_ERR_ $source | cut -d " " -f 3  ))

# while IFS= read -rd ''; do
#    targets+=("$REPLY")
# done < <(grep MBEDTLS_ERR_ /Users/ianic/code/zig/ninja/zig-mbedtls/zig-cache/o/e4954ff27820eeb23e89a87d2dbf4052/cimport.zig)

# check content of array
#declare -p targets

zig_names=()
for str in ${c_names[@]}; do
  parts=(`echo $str | tr '_' ' '`)
  # for p in ${parts[@]}; do
  #      pp=${p:0:1}"$(tr '[:upper:]' '[:lower:]' <<< ${p:1})"
  #      echo "  $p $pp"
  # done

  name=""
  for p in ${parts[@]:2}; do
       pp=${p:0:1}"$(tr '[:upper:]' '[:lower:]' <<< ${p:1})"
       name=$name${pp}
       #echo "  $p $pp"
  done

  #echo $str $name
  zig_names+=($name)
done

# for value in "${zig_names[@]}"; do
#      echo $value
# done

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
