module DuoSecurity
  class Attempt
    def initialize(username)
      @username = username
    end

    def login!
      true
    end
  end
end
