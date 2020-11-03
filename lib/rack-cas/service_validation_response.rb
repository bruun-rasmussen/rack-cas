module RackCAS
  class ServiceValidationResponse
    class AuthenticationFailure < StandardError; end
    class RequestInvalidError < AuthenticationFailure; end
    class TicketInvalidError < AuthenticationFailure; end
    class ServiceInvalidError < AuthenticationFailure; end
    class MissingPGT < AuthenticationFailure; end
    class CASUnavailable < AuthenticationFailure; end

    REQUEST_HEADERS = { 'Accept' => '*/*' }

    def initialize(url)
      @url = URL.parse(url)
    end

    def user
      if success?
        xml.xpath('/cas:serviceResponse/cas:authenticationSuccess/cas:user').text
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

    def extra_attributes
      attrs = {}

      raise AuthenticationFailure, failure_message unless success?

      # Jasig style
      if attr_node = xml.at('/cas:serviceResponse/cas:authenticationSuccess/cas:attributes')
        attr_node.children.each do |node|
          if node.is_a? Nokogiri::XML::Element
            attrs[node.name] = node.text
          end
        end

      # RubyCas-Server style
      else
        xml.at('/cas:serviceResponse/cas:authenticationSuccess').children.each do |node|
          if node.is_a? Nokogiri::XML::Element
            if !node.namespace || !node.namespace.prefix == 'cas'
              # TODO: support JSON encoding
              attrs[node.name] = YAML.load node.text.strip
            end
          end
        end
      end

      attrs
    end

    def pgt_iou
      if xml.xpath("cas:serviceResponse//cas:proxyGrantingTicket").empty?
        fail MissingPGT, "CAS was probably unable to connect to the pgt_callback_url"
      end

      xml.xpath("cas:serviceResponse//cas:proxyGrantingTicket").text
    end

    protected

    def success?
      @success ||= !!xml.at('/cas:serviceResponse/cas:authenticationSuccess')
    end

    def authentication_failure
      @authentication_failure ||= xml.at('/cas:serviceResponse/cas:authenticationFailure')
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

      unless response.code.to_i < 400
        fail CASUnavailable, @response.body
      end

      @response
    end

    def xml
      return @xml unless @xml.nil?

      @xml = Nokogiri::XML(response.body)
    end
  end
end
