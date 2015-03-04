require 'open-uri'
require 'net/http'
require 'test/unit'
require 'securerandom'
require 'tempfile'

require 'server'

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


class TestServer < Test::Unit::TestCase

  def teardown
    $tests_failed = true unless passed?
  end

  def test_http_1_1_get
    2000.times do
      response = Net::HTTP.get_response(URI("#{$server.http_uri}/index.html"))
      assert_equal "Hello Ruby", response.body.strip
    end
  end

  def test_https_1_1_get
    uri = URI("#{$server.https_uri}/index.html")
    response = open(uri, ssl_verify_mode: OpenSSL::SSL::VERIFY_NONE)
    body = response.readlines.join("")
    assert_equal "Hello Ruby", body.strip
  end

  if ENV["HAVE_NGHTTP"]

    def test_nghttp2_get_cleartext_once
      get URI($server.http_uri)
    end

    def test_nghttp2_get_cleartext_lots
      get URI($server.http_uri), count: 50
    end

    def test_nghttp2_post_cleartext_once
      post URI($server.http_uri)
    end

    def test_nghttp2_get_tls_once
      get URI($server.https_uri)
    end

    def test_nghttp2_get_tls_lots
      get URI($server.https_uri), cout: 50
    end

    def test_nghttp2_get_tls_multiply
      count = 50
      uri = URI($server.https_uri)
      response_str = `nghttp #{uri} -m #{count}`
      responses = response_str.split("\n")
      assert_equal count, responses.count do |line|
        line =~ /\AHello nghttp2/
      end
    end

    def test_nghttp2_get_tls_with_contination
      get URI($server.https_uri), continuation: true
    end

    def test_nghttp2_post_tls_once
      post URI($server.https_uri)
    end

    def test_nghttp2_post_tls_with_padding
      post URI($server.https_uri), 250
    end

    def test_nghttp2_upgrade
      uri = URI($server.http_uri)
      response = `nghttp #{uri} -u -v`
      assert_match "HTTP Upgrade success", response
      assert_match "Hello nghttp2", response
    end

  end

  private

  def get(uri, options = {})
    count = options[:count] || 1
    uris = (1..count).map { |i| "#{uri.to_s}/#{i}" }
    response_str = `nghttp #{uris.join(" ")} #{"--continuation" if options[:continuation]}`
    responses = response_str.split("\n")
    assert_equal count, responses.count do |line|
      line =~ /\AHello nghttp2/
    end
  end

  def post(uri, padding = 0)
    random_string = SecureRandom.hex
    file = Tempfile.new("post")
    begin
      file.write random_string
      file.flush

      response = `nghttp #{uri} --data=#{file.path} --padding=#{padding}`
      assert_equal random_string, response

    ensure
      file.close
      file.unlink
    end
  end

end

