require 'rack-cas/url'
require 'rack-cas/service_validation_response'
require 'rack-cas/pgt_validation_response'

module RackCAS
  class Server
    def initialize(url)
      @url = RackCAS::URL.parse(url)
    end

    def login_url(service_url, params = {})
      service_url = URL.parse(service_url)
      if params[:gateway]
        service_url.add_params cas: 'guest'
      end
      @url.dup.append_path('login').add_params({service: service_url.to_s}.merge(params))
    end

    def logout_url(params = {})
      @url.dup.tap do |url|
        url.append_path('logout')
        url.add_params(params) unless params.empty?
      end
    end

    def validate_service(service_url, ticket, pgt_callback_url=nil)
      response = ServiceValidationResponse.new validate_service_url(service_url, ticket, pgt_callback_url)
      if pgt_callback_url
        [response.user, response.extra_attributes, response.pgt_iou]
      else
        [response.user, response.extra_attributes]
      end
    end

    def validate_proxy_granting_ticket(service_url, pgt)
      fail ArgumentError.new "Missing Service URL" if service_url.nil?
      fail ArgumentError.new "Missing PGT" if pgt.nil?
      response = PGTValidationResponse.new validate_pgt_url(service_url, pgt)
      response.proxy_ticket
    end

    protected

    def validate_service_url(service_url, ticket, pgt_callback_url=nil)
      service_url = URL.parse(service_url).remove_param('ticket').to_s
      params = { service: service_url, ticket: ticket }
      params[:pgtUrl] = pgt_callback_url unless pgt_callback_url.nil?
      @url.dup.append_path('serviceValidate').add_params(params)
    end

    def validate_pgt_url(service_url, proxy_granting_ticket)
      puts "cas: validate_pgt_url(#{service_url}, #{proxy_granting_ticket})"
      @url.dup.append_path('proxy').add_params(service: service_url, pgt: proxy_granting_ticket)
    end
  end
end