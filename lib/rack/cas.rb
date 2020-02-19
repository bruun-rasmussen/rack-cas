require 'rack'
require 'addressable/uri'
require 'rack-cas/server'
require 'rack-cas/cas_request'

TICKETS = {}

class Rack::CAS
  attr_accessor :server_url

  def initialize(app, config={})
    @app = app
    @server_url = config.delete(:server_url)
    @session_store = config.delete(:session_store)
    @config = config || {}

    raise ArgumentError, 'server_url is required' if @server_url.nil?
    if @session_store && !@session_store.respond_to?(:destroy_session_by_cas_ticket)
      raise ArgumentError, 'session_store does not support single-sign-out'
    end
  end

  def call(env)
    request = Rack::Request.new(env)
    cas_request = CASRequest.new(request)

    if cas_request.path_matches? @config[:exclude_paths] || @config[:exclude_path]
      return @app.call(env)
    end

    if cas_request.ticket_validation?
      log env, 'rack-cas: Intercepting ticket validation request.'

      begin
        user, extra_attrs, pgt_iou = get_user(request.url, cas_request.ticket, pgt_callback_url(request))
        proxy_ticket = get_proxy_ticket(pgt_iou) if @config[:proxy_service_url]
      rescue RackCAS::ServiceValidationResponse::TicketInvalidError
        log env, 'rack-cas: Invalid ticket. Redirecting to CAS login.'

        return redirect_to server.login_url(cas_request.service_url).to_s
      end

      store_session request, user, cas_request.ticket, extra_attrs, proxy_ticket
      return redirect_to cas_request.service_url
    end

    if cas_request.pgt_callback?
      log env, 'rack-cas: PGT Callback request.'
      store_pgt(cas_request, env)
      return [200, {'Content-Type' => 'text/plain'}, ['CAS PGT Callback request intercepted.']]
    end

    if cas_request.logout?
      log env, 'rack-cas: Intercepting logout request.'

      request.session.clear
      return redirect_to server.logout_url(request.params).to_s
    end

    if cas_request.single_sign_out? && @session_store
      log env, 'rack-cas: Intercepting single-sign-out request.'

      @session_store.destroy_session_by_cas_ticket(cas_request.ticket)
      return [200, {'Content-Type' => 'text/plain'}, ['CAS Single-Sign-Out request intercepted.']]
    end

    if cas_request.session_exists?

      if cas_request.guest_param?
        # Session exists, so there is no need to keep the CAS query parameter
        return redirect_to RackCAS::URL.parse(request.url).remove_param('cas').to_s
      end

    elsif @config[:gateway_mode] && !skip_gateway?(cas_request)

      request.session['cas_anonymous'] = true
      log env, 'rack-cas: Gateway. Redirecting to ' + server.login_url(request.url, gateway: true ).to_s
      log env, 'rack-cas: request.url = ' + request.url
      return redirect_to server.login_url(request.url, gateway: true ).to_s

    end

    response = @app.call(env)

    response_status, response_headers, response_body = response

    return response unless response_status == 401

    # Unauthorized:

    is_script = request.get_header('Accept') =~ JAVASCRIPT_MIME_TYPE || response[1]['Content-Type'] =~ JAVASCRIPT_MIME_TYPE

    return response if is_script

    return turbolinks_force_reload if turbolinks? env

    log env, 'rack-cas: Intercepting 401 access denied response. Redirecting to CAS login.'
    redirect_to server.login_url(request.url).to_s

  end

  JAVASCRIPT_MIME_TYPE = Regexp.union 'application/javascript', 'text/javascript'

  protected

  def reload_javascript status
    Rack::Response.new "window.location.reload();", status, { 'Content-Type' => 'application/javascript' }
  end

  def turbolinks_force_reload
    html = <<~HTML
    <!doctype html>
    <html lang=en>
      <head>
        <meta charset=utf-8>
        <title></title>
        <script>window.location.reload();</script>
      </head>
      <body>
      </body>
    </html>
    HTML
    [ 200, {}, [ html ] ]
  end

  def server
    @server ||= RackCAS::Server.new(@server_url)
  end

  def turbolinks? env
    env['HTTP_TURBOLINKS_REFERRER'].to_s != ''
  end

  def get_user(service_url, ticket, pgt_callback_url)
    server.validate_service(service_url, ticket, pgt_callback_url)
  end

  def get_proxy_ticket(pgt_iou)
    proxy_service_url = @config[:proxy_service_url]
    pgt = get_pgt(pgt_iou)
    server.validate_proxy_granting_ticket(proxy_service_url, pgt)
  end

  def store_session(request, user, ticket, extra_attrs = {}, proxy_ticket)
    if @config[:extra_attributes_filter]
      filter = Array(@config[:extra_attributes_filter]).map(&:to_s)
      extra_attrs = extra_attrs.select { |key, val| filter.include? key }
    end
    request.session['cas'] = {
      'user' => user,
      'ticket' => ticket,
      'extra_attributes' => extra_attrs
    }
    request.session['cas']['proxy_ticket'] = proxy_ticket
    request.session['cas_anonymous'] = false
  end

  def redirect_to(url, status=302)
    [ status, { 'Location' => url, 'Content-Type' => 'text/plain' }, ["Redirecting you to #{url}"] ]
  end

  def log(env, message, level = :info)
    if env['rack.logger']
      env['rack.logger'].send(level, message)
    else
      env['rack.errors'].write(message)
    end
  end

  def ticket_store
    @ticket_store ||= @config.fetch(:ticket_store).call
  end

  def pgt_callback_url(request)
    request.scheme + '://' + request.host_with_port + request.script_name + '/pgt_callback'
  end

  def get_pgt(pgt_iou)
    ticket_store.read(pgt_iou)
  end

  def store_pgt(cas_request, env)
    # CAS actually calls back twice, the first time with no params
    return unless cas_request.pgt_params

    pgt_iou, pgt_id = cas_request.pgt_params
    log env, "store #{pgt_iou} #{pgt_id}"

    ticket_store.write pgt_iou, pgt_id
  end

  def skip_gateway?(request)
    request.guest_param? || [
      /Googlebot/,
      /Baiduspider/,
      /Bingbot/,
      /Yahoo!/,
      /iaskspider/,
      /facebookexternalhit/,
      /Twitterbot/,
      /LinkedInBot/,
      /Google \(\+https:\/\/developers.google.com\/\+\/web\/snippet\/\)/,
      /Pinterest/
    ].any? { |pattern| pattern =~ request.user_agent }
  end
end
