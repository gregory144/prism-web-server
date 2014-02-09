class Node

  attr_accessor :value
  attr_accessor :left, :right
  attr_accessor :index, :left_index, :right_index

  def find(key)
    unless key.nil?
      if @left && key[0] == "0"
        @left.find(key[1..-1] )
      elsif @right && key[0] == "1"
        @right.find(key[1..-1])
      else
        @value
      end
    end
  end

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

  def preorder(&visitor)
    visitor.call(self)
    @left.preorder(&visitor) if @left
    @right.preorder(&visitor) if @right
  end

  def postorder(&visitor)
    @left.postorder(&visitor) if @left
    @right.postorder(&visitor) if @right
    visitor.call(self)
  end

end

value = 0
text = File.open('huffman_requests.txt').read
table = []
text.each_line do |line|
  components = line.split(/\s+/)
  binary = components.find do |component|
    /^\|/ =~ component
  end.gsub(/\|/, '')
  table[value] = binary
  value += 1
end

tree = Node.new
table.each_with_index do |k, v|
  tree.insert(k, v)
end

c_rep = []

tree.postorder do |node|
  node.index = c_rep.length
  node.left_index = node.left.index if node.left
  node.right_index = node.right.index if node.right
  c_rep.push(node)
end

start_index = tree.index
puts %Q(
#include "huffman.h"

static const size_t huffman_decoder_size = #{c_rep.length};

static const huffman_entry_t huffman_decoder_table[] = {

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

if false

  # find via tree
  v = tree.find("111111111111111111111011001")
  puts "75 =? #{v}"

  # find via c_rep table
  values = []

  chars = " 1101111 11101011 11101100 11101101 11101110 1110000 ".gsub(/\s/, '').chars
  puts "chars: #{chars.join}"

  curr = c_rep[start_index]
  char = chars.shift
  while !curr.nil? && !char.nil? do
    if curr.value
      puts "found #{curr.value}"
      values.push(curr.value)
      puts "chars: #{chars.join}"
      curr = c_rep[start_index]
    elsif char == "0"
      puts "going left"
      curr = c_rep[curr.left_index]
      char = chars.shift
    elsif char == "1"
      puts "going right"
      curr = c_rep[curr.right_index]
      char = chars.shift
    else
      throw
    end
  end

  values.push(curr.value)
  puts "value: #{values.map { |j| j.chr }.join}"
end

