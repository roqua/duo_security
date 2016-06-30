module DuoSecurity
  class Attempt
    def initialize(api, username)
      @api      = api
      @username = username
    end

    def login!
      preauth = @api.preauth(@username)
      factor  = preauth["factors"].fetch("default")

      @api.auth(@username, "auto", {"auto" => factor})
    rescue API_Base::UnknownUser
      false
    end
  end
end
