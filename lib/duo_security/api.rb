#!/usr/bin/env ruby

module DuoSecurity
  class API
    def self.new(host, secret_key, integration_key, api_version = 1)
      case api_version
      when 1
        ApiV1.new(host, secret_key, integration_key)
      when 2
        ApiV2.new(host, secret_key, integration_key)
      else
        raise "API version #{api_version} not supported"
      end
    end
  end # API
end # DuoSecurity

