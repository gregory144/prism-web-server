require 'tmpdir'
require 'singleton'
require 'timeout'
require 'socket'

class Server

  include Singleton

  def initialize
    @pids = []

    @hostname = "0.0.0.0"
    @http_port, @https_port = find_open_ports

    @dir = Dir.mktmpdir("prism-end-to-end")

    @binary_path = ENV["PRISM_EXECUTABLE"]
    @files_plugin_path = ENV["FILES_PLUGIN_LIB"]
    @debug_plugin_path = ENV["DEBUG_PLUGIN_LIB"]

    generate_self_signed_cert
  end

  def start
    cmd = "#{@binary_path} -l #{http_uri} -l #{https_uri} -p #{@debug_plugin_path} -L INFO -o #{@dir}/server.log"
    @pids.push(spawn(cmd, chdir: @dir))

    # wait for the server to start accepting connections
    is_accepting_connections?(@hostname, @http_port)
    is_accepting_connections?(@hostname, @https_port)
  end

  def kill
    return if @pids.empty?
    pid = @pids.pop
    Process.kill('SIGTERM', pid)
    Process.wait(pid)
  end

  def destroy_working_dir
    FileUtils.remove_entry(@dir)
  end

  def working_dir
    @dir
  end

  def http_uri
    "http://#{@hostname}:#{@http_port}"
  end

  def https_uri
    "https://#{@hostname}:#{@https_port}"
  end

  private

  def generate_self_signed_cert
    openssl_pid = spawn("openssl req -x509 -newkey rsa:2048 -keyout #{@dir}/key.pem -out #{@dir}/cert.pem -days 365 -nodes -subj '/C=AU/ST=Victoria/L=Melbourne/O=Prism/OU=Prism/CN=0.0.0.0'")
    Process.wait(openssl_pid)
  end

  def find_open_ports
    first = (10000..20000).find do |i|
      is_port_open?(@hostname, i) && is_port_open?( @hostname, i + 1)
    end
    [first, first + 1]
  end

  def is_port_open?(ip, port)
    begin
      Timeout::timeout(1) do
        begin
          s = TCPServer.new(ip, port)
          s.close
          return true
        rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
          return false
        end
      end
    rescue Timeout::Error
    end

    return false
  end

  def is_accepting_connections?(ip, port)
    Timeout::timeout(1) do
      while true
        begin
          s = TCPSocket.new(ip, port)
          s.close
          return true
        rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
          sleep 0.1
          # wait for it!
        end
      end
    end

    return false
  end

end
