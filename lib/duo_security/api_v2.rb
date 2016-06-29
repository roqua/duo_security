module DuoSecurity
  class ApiV2 < API_Base
    def initialize(host, secret_key, integration_key)
      @host = host
      @skey = secret_key
      @ikey = integration_key
      @now = Time.now.strftime("%a, %d %b %Y %T %z")

      self.class.base_uri "https://#{@host}/auth/v2"
    end

    def check
      auth = sign("get", @host, "/auth/v2/check", {}, @skey, @ikey)
      response = self.class.get("/check", headers: {"Authorization" => auth})

      # TODO use parsed_response.fetch(...) when content-type is set correctly
      response["response"] == "valid"
    end

    def preauth(user)
      response = post("/preauth", {"username" => user})["response"]

      raise API_Base::UnknownUser, response.fetch("status") if response.fetch("result") == "enroll" || response.fetch("result") == "deny"

      return response
    end

    def auth(user, factor, factor_params)
      raise ArgumentError.new("Factor should be one of #{FACTORS.join(", ")}") unless FACTORS.include?(factor)

      params = {"username" => user, "factor" => factor}.merge(factor_params)
      response = post("/auth",params)

      response["response"]["result"] == "allow"
    end

    protected

    def post(path, params = {})
      auth = sign("post", @host, "/auth/v2#{path}", params, @skey, @ikey)
      self.class.post(path,
                      headers: {"Authorization" => auth,
                                "Content-Type" => "application/x-www-form-urlencoded",
                                "Date" => @now},
                      body: params)
    end

    def hmac_sha1(key, data)
      OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha1'), key, data.to_s)
    end

    def sign(method, host, path, params, skey, ikey)
      canon = [@now, method.upcase, host.downcase, path]

      args = []
      for key in params.keys.sort
        val = params[key]
        args << "#{CGI.escape(key)}=#{CGI.escape(val)}"
      end

      canon << args.join("&")
      canon = canon.join("\n")

      sig = hmac_sha1(skey, canon)
      auth = "#{ikey}:#{sig}"

      encoded = Base64.encode64(auth).split("\n").join("")

      return "Basic #{encoded}"
    end
  end
end
