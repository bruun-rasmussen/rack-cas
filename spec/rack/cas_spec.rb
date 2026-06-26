require 'spec_helper'

describe Rack::CAS do
  let(:server_url) { 'http://example.com/cas' }
  let(:app_options) { {} }
  let(:ticket) { 'ST-0123456789ABCDEFGHIJKLMNOPQRS' }

  def app
    cas_test_app app_options
  end

  describe 'public request' do
    subject { get '/public' }
    its(:status) { should eql 200 }
  end

  describe 'auth required request' do
    subject { get '/private' }
    its(:status) { should eql 302 }
    its(:location) { should match %r{http://example.com/cas/login\?service=http%3A%2F%2Fexample.org%2Fprivate} }
  end

  describe 'ticket validation request' do
    subject { get '/private?search=blah&ticket=ST-0123456789ABCDEFGHIJKLMNOPQRS' }
    its(:status) { should eql 302 }
    its(:location) { should eql 'http://example.org/private?login=true&search=blah' }

    context 'without additional query parameters' do
      subject { get '/private?ticket=ST-0123456789ABCDEFGHIJKLMNOPQRS' }
      its(:status) { should eql 302 }
      its(:location) { should eql 'http://example.org/private?login=true' }
    end

    context 'with extra_attributes_filter set' do
      let(:app_options) { { extra_attributes_filter: [:cn, :mail] } }

      before { get '/private?ticket=ST-0123456789ABCDEFGHIJKLMNOPQRS' }
      subject { last_request.session['cas']['extra_attributes'] }
      it { should have_key 'cn' }
      it { should have_key 'mail' }
      it { should_not have_key 'title' }
    end

    context 'with an invalid ticket' do
      before { allow_any_instance_of(RackCAS::ServiceValidationResponse).to receive(:user).and_raise(RackCAS::ServiceValidationResponse::TicketInvalidError) }
      its(:status) { should eql 302 }
      its(:location) { should eql 'http://example.com/cas/login?service=http%3A%2F%2Fexample.org%2Fprivate%3Flogin%3Dtrue%26search%3Dblah' }
    end
  end

  describe 'logout request' do
    context 'without params' do
      subject { get '/logout' }
      its(:status) { should eql 302 }
      its(:location) { should eql 'http://example.com/cas/logout' }
    end

    context 'with params' do
      subject { get '/logout', gateway: 'true', service: 'http://example.com' }
      its(:status) { should eql 302 }
      its(:location) { should eql 'http://example.com/cas/logout?gateway=true&service=http%3A%2F%2Fexample.com' }
    end
  end

  describe 'single sign out request' do
    let(:app_options) {
      session_store = double('session_store')
      allow(session_store).to receive(:destroy_session_by_cas_ticket).and_return(1)
      expect(session_store).to receive(:destroy_session_by_cas_ticket).with(ticket)

      { session_store: session_store }
    }

    subject { post "/?logoutRequest=#{CGI.escape(fixture('single_sign_out_request.xml'))}" }
    its(:status) { should eql 200 }
    its(:body) { should eql 'CAS Single-Sign-Out request intercepted.' }
  end

  describe 'excluded request' do
    let(:app_options) { { exclude_path: '/private' } }

    subject { get '/private' }
    its(:status) { should eql 401 }
    its(:body) { should eql 'Authorization Required' }
  end

  describe 'gateway_mode' do
    let(:app_options) { { gateway_mode: true } }

    context 'when no session exists' do
      subject { get '/public', {}, { 'HTTP_ACCEPT' => 'text/html' } }

      its(:status) { should eql 302 }
      it 'should use the requested url as the service url without adding a guest parameter' do
        expect(subject.location).to match(%r{http://example.com/cas/login\?gateway=true&service=http%3A%2F%2Fexample.org%2Fpublic})
      end

      context 'when the requested url has a guest parameter' do
        subject { get '/public?cas=guest' }
        its(:status) { should eql 200 }
      end

      context 'when the referer is the CAS server' do
        subject { get '/public', {}, { 'HTTP_ACCEPT' => 'text/html', 'HTTP_REFERER' => 'http://example.com/cas/login' } }
        its(:status) { should eql 200 }
      end

    end

    context 'when an anonymous session exists' do
      subject { get '/public',  {}, "rack.session" =>  {'cas_anonymous' => true}}
      its(:status) { should eql 200 }

      context 'when the requested url has a guest parameter' do
        subject { get '/public?cas=guest',  {}, "rack.session" =>  {'cas_anonymous' => true} }
        its(:status) { should eql 302 }
        its(:location) { should eql 'http://example.org/public' }
      end
    end

    context 'when an authenticated session exists' do
      subject { get '/public',  {}, "rack.session" =>  { 'cas' => { user: 42} } }
      its(:status) { should eql 200 }

      context 'when the requested url has a guest parameter' do
        subject { get '/public?cas=guest',  {}, "rack.session" =>  {'cas_anonymous' => true} }
        its(:status) { should eql 302 }
        its(:location) { should eql 'http://example.org/public' }
      end
    end
  end

  describe 'proxying' do
    let(:app_options) { { proxy: true } }


  end
end
