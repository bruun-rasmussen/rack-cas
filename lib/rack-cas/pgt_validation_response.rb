module RackCAS
  class PGTValidationResponse
    class AuthenticationFailure < StandardError; end
    class RequestInvalidError < AuthenticationFailure; end
    class TicketInvalidError < AuthenticationFailure; end
    class ServiceInvalidError < AuthenticationFailure; end

    REQUEST_HEADERS = { 'Accept' => '*/*' }

    def initialize(url)
      @url = URL.parse(url)
    end

    def proxy_ticket
      if success?
        xml.xpath("cas:serviceResponse//cas:proxyTicket").text
      else
        case failure_code
        when 'INVALID_REQUEST'
          raise RequestInvalidError, failure_message
        when 'INVALID_TICKET'
          raise TicketInvalidError, failure_message
        when 'INVALID_SERVICE'
          raise ServiceInvalidError, failure_message
        else
          raise AuthenticationFailure, failure_message
        end
      end
    end

    protected

    def success?
      @success ||= !!xml.at('/cas:serviceResponse/cas:proxySuccess')
    end

    def authentication_failure
      @authentication_failure ||= xml.at('/cas:serviceResponse/cas:proxyFailure')
    end

    def failure_message
      if authentication_failure
        authentication_failure.text.strip
      end
    end

    def failure_code
      if authentication_failure
        authentication_failure['code']
      end
    end

    def response
      require 'net/http'
      return @response unless @response.nil?

      http = Net::HTTP.new(@url.host, @url.inferred_port)
      http.use_ssl = true if @url.scheme == 'https'

      http.start do |conn|
        @response = conn.get(@url.request_uri, REQUEST_HEADERS)
      end

      @response
    end

    def xml
      return @xml unless @xml.nil?

      @xml = Nokogiri::XML(response.body)
    end
  end
end
