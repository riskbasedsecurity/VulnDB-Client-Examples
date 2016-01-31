class Vulndb

  def self.checkvuldb(cve_id)
      cve_id = cve_id.gsub(/(cve\-)/i,"")
      consumer_key = ""
      consumer_secret = ""
      consumer = OAuth::Consumer.new(consumer_key, consumer_secret,
          :site => "https://vulndb.cyberriskanalytics.com",
          :request_token_path => "/oauth/request_token",
          :authorize_path => "/oauth/authorize",
          :access_token_path => "/oauth/access_token",
          :http_method => :get)
      access_token = OAuth::AccessToken.new consumer
    @response = access_token.get("/api/v1/vulnerabilities/#{cve_id}/find_by_cve_id")
    return @response.body
  end
  def self.is_valid(data)
    kw = /Unable for find vulnerabilities for cve_id /
    regex    = Regexp.new(kw.to_s, Regexp::IGNORECASE | Regexp::MULTILINE)   # => setup the new regex
    if data[0].scan(regex).size  > 0
      return true
    else
      return false
    end    
  end
end