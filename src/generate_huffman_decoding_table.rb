# Generates C language code to support
# decoding huffman codes for hpack

# Represents a node in a huffman tree
class Node

  # the ascii value (if this is a leaf)
  attr_accessor :value

  # the child nodes
  attr_accessor :left, :right

  # the index in the array that this value will
  # be stored in
  attr_accessor :index
  # the index in the array that this value's
  # children will be stored in
  attr_accessor :left_index, :right_index

  def insert(key, v)
    if key[0] == "0"
      @left = Node.new unless @left
      @left.insert(key[1..-1], v)
    elsif key[0] == "1"
      @right = Node.new unless @right
      @right.insert(key[1..-1], v)
    else
      @value = v
    end
  end

  def postorder(&visitor)
    @left.postorder(&visitor) if @left
    @right.postorder(&visitor) if @right
    visitor.call(self)
  end

end

# read binary strings from input
value = 0
text = File.open('huffman_requests.txt').read
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

# insert binary strings into the tree
tree = Node.new
table.each_with_index do |k, v|
  tree.insert(k, v)
end

# construct an array to represent the tree
c_rep = []
tree.postorder do |node|
  node.index = c_rep.length
  node.left_index = node.left.index if node.left
  node.right_index = node.right.index if node.right
  c_rep.push(node)
end

# construct the c language representation of the huffman table
start_index = tree.index
puts %Q(
#include <stdio.h>

#include "huffman.h"

static const size_t huffman_decoder_size = #{c_rep.length};

static const huffman_decoder_entry_t huffman_decoder_table[] = {

)

c_rep.each_with_index do |c, i|
  puts %Q(
    {
      #{i},
      #{c.value || -1},
      #{c.left_index || -1},
      #{c.right_index || -1},
    },
  )
end

puts "};"

