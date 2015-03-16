require 'test/unit'
require 'securerandom'
require 'tempfile'

class TestNghttp < Test::Unit::TestCase

  def teardown
    $tests_failed = true unless passed?
  end

  def test_nghttp2_get_cleartext_once
    get URI($server.http_debug_uri)
  end

  def test_nghttp2_get_cleartext_lots
    get URI($server.http_debug_uri), count: 50
  end

  def test_nghttp2_post_cleartext_once
    post URI($server.http_debug_uri)
  end

  def test_nghttp2_get_tls_once
    get URI($server.https_debug_uri)
  end

  def test_nghttp2_get_tls_lots
    get URI($server.https_debug_uri), count: 50
  end

  def test_nghttp2_get_tls_multiply
    count = 50
    uri = URI($server.https_debug_uri)
    response_str = `nghttp #{uri} -m #{count}`
    assert_equal 0, $?
    responses = response_str.split("\n")
    assert_equal count, responses.count do |line|
      line =~ /\AHello nghttp2/
    end
  end

  def test_nghttp2_get_tls_with_contination
    get URI($server.https_debug_uri), continuation: true
  end

  def test_nghttp2_post_tls_once
    post URI($server.https_debug_uri)
  end

  def test_nghttp2_post_tls_with_padding
    post URI($server.https_debug_uri), 250
  end

  def test_nghttp2_upgrade
    uri = URI($server.http_debug_uri)
    response = `nghttp #{uri} -u -v`
    assert_equal 0, $?
    assert_match "HTTP Upgrade success", response
    assert_match "Hello nghttp2", response
  end

  def test_nghttp2_get_file
   uri = "#{$server.https_files_uri}/gophertiles.html"

    response_str = `nghttp #{uri}`
    assert_equal 0, $?
    assert_match "<h1>Test page</h1>", response_str
  end

  def test_nghttp2_get_assets
   uri = "#{$server.https_files_uri}/gophertiles.html"

    response_str = `nghttp #{uri} --get-assets -n -v`
    assert_equal 0, $?
    puts response_str
    assert_match "NO_ERROR", response_str
  end

  private

  def get(uri, options = {})
    uris = [ uri ]

    count = options[:count] || 1
    uris = (1..count).map { |i| "#{uri.to_s}/#{i}" } if count > 1

    response_str = `nghttp #{uris.join(" ")} #{"--continuation" if options[:continuation]} #{"--get-assets" if options[:get_assets]}`
    assert_equal 0, $?
    responses = response_str.split("\n")
    actual_count = responses.count do |line|
      line =~ /\AHello nghttp2/
    end
    assert_equal count, actual_count
  end

  def post(uri, padding = 0)
    random_string = SecureRandom.hex
    file = Tempfile.new("post")
    begin
      file.write random_string
      file.flush

      response = `nghttp #{uri} --data=#{file.path} --padding=#{padding}`
      assert_equal 0, $?
      assert_equal random_string, response

    ensure
      file.close
      file.unlink
    end
  end

end
