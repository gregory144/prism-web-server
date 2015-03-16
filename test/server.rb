require 'tmpdir'
require 'singleton'
require 'timeout'
require 'socket'
require 'json'

class Server

  include Singleton

  def initialize
    @pids = []

    @hostname = "0.0.0.0"

    @dir = Dir.mktmpdir("prism-end-to-end")

    @binary_path = ENV["PRISM_EXECUTABLE"]
    @files_plugin_path = ENV["FILES_PLUGIN_LIB"]
    @debug_plugin_path = ENV["DEBUG_PLUGIN_LIB"]
    @fixtures_path = ENV["FIXTURES_PATH"]

    generate_self_signed_cert
  end

  def start
    @http_debug_port, @https_debug_port = find_open_ports
    generate_debug_config
    cmd = "#{@binary_path} -f #{@dir}/debug-server.json"
    @pids.push(spawn(cmd, chdir: @dir))

    # wait for the server to start accepting connections
    is_accepting_connections?(@hostname, @http_debug_port)
    is_accepting_connections?(@hostname, @https_debug_port)
    puts "Debug started on #{@http_debug_port} and #{@https_debug_port}"

    @http_files_port, @https_files_port = find_open_ports
    generate_files_config
    copy_fixture_files
    cmd = "#{@binary_path} -f #{@dir}/files-server.json"
    @pids.push(spawn(cmd, chdir: @dir))

    is_accepting_connections?(@hostname, @http_files_port)
    is_accepting_connections?(@hostname, @https_files_port)
    puts "Files started on #{@http_files_port} and #{@https_files_port}"
  end

  def kill
    @pids.each do |pid|
      Process.kill('SIGTERM', pid)
      Process.wait(pid)
    end
  end

  def destroy_working_dir
    FileUtils.remove_entry(@dir)
  end

  def working_dir
    @dir
  end

  def http_debug_uri
    "http://#{@hostname}:#{@http_debug_port}"
  end

  def https_debug_uri
    "https://#{@hostname}:#{@https_debug_port}"
  end

  def http_files_uri
    "http://#{@hostname}:#{@http_files_port}"
  end

  def https_files_uri
    "https://#{@hostname}:#{@https_files_port}"
  end

  private

  def generate_self_signed_cert
    openssl_pid = spawn("openssl req -x509 -newkey rsa:2048 -keyout #{@dir}/key.pem -out #{@dir}/cert.pem -days 365 -nodes -subj '/C=AU/ST=Victoria/L=Melbourne/O=Prism/OU=Prism/CN=0.0.0.0'")
    Process.wait(openssl_pid)
  end

  def generate_debug_config
    config = {
      private_key_path: "#{@dir}/key.pem",
      certificate_path: "#{@dir}/cert.pem",

      log_path: "#{@dir}/debug-server.log",
      log_level: "INFO",

      plugins: [
        {
          path: @debug_plugin_path,
        }
      ],

      listen: [
        {
          secure: true,
          port: @https_debug_port,
          ip_address: @hostname
        },
        {
          secure: false,
          port: @http_debug_port,
          ip_address: @hostname
        }
      ]
    }
    File.open("#{@dir}/debug-server.json", 'w') do |f|
      f.write(JSON.generate(config))
    end
  end

  def generate_files_config
    config = {
      private_key_path: "#{@dir}/key.pem",
      certificate_path: "#{@dir}/cert.pem",

      log_path: "#{@dir}/file-server.log",
      log_level: "INFO",

      plugins: [
        {
          path: @files_plugin_path,
        }
      ],

      listen: [
        {
          secure: true,
          port: @https_files_port,
          ip_address: @hostname
        },
        {
          secure: false,
          port: @http_files_port,
          ip_address: @hostname
        }
      ]
    }
    File.open("#{@dir}/files-server.json", 'w') do |f|
      f.write(JSON.generate(config))
    end
  end

  def copy_fixture_files
    FileUtils.cp_r "#{@fixtures_path}/.", @dir, verbose: true
  end

  def find_open_ports
    first = (10000..20000).find do |i|
      is_port_open?(@hostname, i) && is_port_open?(@hostname, i + 1)
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
        rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::EADDRINUSE
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
