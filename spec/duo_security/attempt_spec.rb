require 'minitest/autorun'
require_relative '../../lib/duo_security/attempt'

module DuoSecurity
  describe Attempt do
    let(:api) { API.new(ENV["DUO_HOST"], ENV["DUO_SKEY"], ENV["DUO_IKEY"]) }

    describe 'when using push notifications' do
      it 'returns true if the user accepts the login' do
        VCR.use_cassette("attempt_allowed") do
          Attempt.new(api, "marten").login!.must_equal true
        end
      end

      it 'returns false if the user denies the login' do
        VCR.use_cassette("attempt_disallowed") do
          Attempt.new(api, "marten").login!.must_equal false
        end
      end

      it 'returns false if the user is not known' do
        VCR.use_cassette("attempt_user_unknown") do
          Attempt.new(api, "unknown").login!.must_equal false
        end
      end
    end
  end
end