#!/usr/bin/env ruby

module DuoSecurity
  class API_Base
  class UnknownUser < StandardError; end
    require 'cgi'
    require 'httparty'
    FACTORS = ["auto", "passcode", "phone", "sms", "push"]
    include HTTParty
    ssl_ca_file File.expand_path(File.join(File.dirname(__FILE__), "..", "..", "data", "ca-bundle.crt"))

    def ping
      response = self.class.get("/ping")
      response.parsed_response.fetch("response") == "pong"
    end
  end
end
