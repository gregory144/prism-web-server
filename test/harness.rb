require 'test/unit'

require 'server'
require 'nghttp' if ENV['HAVE_NGHTTP']
require 'ruby_http'

Test::Unit.at_start do
  begin
    $tests_failed = false
    $server = Server.instance
    $server.start
  rescue
    puts "Server failed to start: #{$!.inspect}"
    $server.kill
    exit 1
  end
end

Test::Unit.at_exit do
  $server.kill
  if $tests_failed
    puts "Keeping working directory: #{$server.working_dir}"
  else
    $server.destroy_working_dir
  end
end


