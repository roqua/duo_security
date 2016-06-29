require "minitest/autorun"
require "vcr"
require_relative "../../lib/duo_security/api"
require_relative "../../lib/duo_security/api_base"
require_relative "../../lib/duo_security/api_v1"
require_relative "../../lib/duo_security/api_v2"

VCR.configure do |c|
  c.cassette_library_dir = "fixtures/vcr"
  c.hook_into :webmock
  c.allow_http_connections_when_no_cassette = true
  c.before_http_request(:real?) do |request|
    puts "Cassette #{VCR.current_cassette.name} being recorded. Take appropriate actions on your phone."
  end
end

module DuoSecurity
  versions = [1, 2]
  versions.each do |v|
    describe API do
      let(:host) { ENV["DUO_HOST"] }
      let(:skey) { ENV["DUO_SKEY"] }
      let(:ikey) { ENV["DUO_IKEY"] }
      let(:user) { ENV["DUO_USER"] }

      describe "#ping (v#{v})" do
        it "succeeds (v#{v})" do
          VCR.use_cassette("api_ping_success_v#{v}") do
            duo = API.new(host, skey, ikey)
            duo.ping.must_equal true
          end
        end
      end

      describe "#check (v#{v})" do
        it "succeeds with correct credentials (v#{v})" do
          VCR.use_cassette("api_check_success_v#{v}") do
            duo = API.new(host, skey, ikey)
            duo.check.must_equal true
          end
        end

        it "fails with incorrect skey (v#{v})" do
          VCR.use_cassette("api_check_wrong_skey_v#{v}") do
            duo = API.new(host, "wrong", ikey)
            duo.check.must_equal false
          end
        end

        it "fails with incorrect ikey (v#{v})" do
          VCR.use_cassette("api_check_wrong_ikey_v#{v}") do
            duo = API.new(host, skey, "wrong")
            duo.check.must_equal false
          end
        end
      end

      describe "#preauth (v#{v})" do
        it "returns a list of possible factors (#{v})" do
          VCR.use_cassette("api_preauth_v#{v}") do
            duo = API.new(host, skey, ikey)
            result = duo.preauth(user)
            result["factors"].must_equal({"1" => "push1",
                                          "2" => "sms1",
                                          "default" => "push1"})
            result["result"].must_equal("auth")
          end
        end

        it "raises when user does not exist (v#{v})" do
          VCR.use_cassette("api_preauth_unknown_user_v#{v}") do
            duo = API.new(host, skey, ikey)
            -> { duo.preauth("unknown") }.must_raise(API_Base::UnknownUser)
          end
        end
      end

      describe "#auth (v#{v})" do
        let(:duo) { API.new(host, skey, ikey) }

        it "returns true if user OKs the request (#{v})" do
          VCR.use_cassette("api_auth_user_accepts_v#{v}") do
            result = duo.auth(user, "push", "phone" => "phone1")
            result.must_equal(true)
          end
        end

        it "returns false if the user denies the requestas a mistake (#{v})" do
          VCR.use_cassette("api_auth_user_denies_mistake_v#{v}") do
            result = duo.auth(user, "push", "phone" => "phone1")
            result.must_equal(false)
          end
        end

        it "returns false if the user denies the request as a fraudulent attack (#{v})" do
          VCR.use_cassette("api_auth_user_denies_fraud_v#{v}") do
            result = duo.auth(user, "push", "phone" => "phone1")
            result.must_equal(false)
          end
        end

        it "raises an exception when factor is unknown (v#{v})" do
          -> { duo.auth(user, "something") }.must_raise(ArgumentError)
        end
      end
    end
  end
end
