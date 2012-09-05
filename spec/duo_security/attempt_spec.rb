require 'minitest/autorun'
require_relative '../../lib/duo_security/attempt'

module DuoSecurity
  describe Attempt do
    describe 'when using push notifications' do
      it 'returns true if the user accepts the login' do
        Attempt.new("marten").login!.must_equal true
      end

      it 'returns false if the user denies the login'
    end
  end
end