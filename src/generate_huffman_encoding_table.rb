# Generates C language code to support
# encoding header data using huffman codes
# for hpack

# read binary strings from input
value = 0
text = File.open('huffman_responses.txt').read
table = []
text.each_line do |line|
  components = line.split(/\s+/)
  # find the column that starts with a '|'
  binary = components.find do |component|
    /^\|/ =~ component
  end.gsub(/\|/, '')
  table[value] = binary
  value += 1
end

# construct the c language representation of the huffman table
puts %Q(
#include <stdio.h>

#include "huffman.h"

static const size_t huffman_encoder_size = #{table.length};

static const huffman_encoder_entry_t huffman_encoder_table[] = {

)

# insert binary strings into the tree
table.each_with_index do |binary_string, value|
  hex = "0x%02x" % binary_string.to_i(2)
  puts %Q(
    {
      #{value},
      #{hex},
      #{binary_string.length}
    },
  )
end


puts "};"

