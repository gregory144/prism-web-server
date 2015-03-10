require 'open-uri'
require 'net/http'
require 'test/unit'
require 'openssl'

class TestRubyHttp < Test::Unit::TestCase

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
    100.times do
      response = open(uri, ssl_verify_mode: OpenSSL::SSL::VERIFY_NONE)
      body = response.readlines.join("")
      assert_equal "Hello Ruby", body.strip
    end
  end

end

