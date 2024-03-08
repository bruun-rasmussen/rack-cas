require 'spec_helper'
require 'rack-cas/url'

describe RackCAS::URL do
  let(:url_string) { 'http://example.com/path?param1=value1&param2=value2' }
  let(:url) { RackCAS::URL.parse(url_string) }

  describe :'self.parse' do
    let(:url_string) { 'http://example.com?param 1=value+1' }
    subject { url.to_s }
    it { should match /%20/ }
    it { should_not match /\+/ }
  end

  describe :append_path do
    subject { url.append_path('appended-path') }
    its(:path) { should eql '/path/appended-path' }
  end

  describe :add_params do
    subject { url.add_params(appended: 'param') }
    its(:query) { should eql 'appended=param&param1=value1&param2=value2' }

    # Addresses MODERN-8KN: https://sentry.bruun-rasmussen.dk/sentry/modern/issues/81995
    # This issue was caused by a confluence of factors:
    # 1. The params hash given to the #add_params method uses symbols as keys, whereas the Addressable::URI#query_values
    #    method used by the #add_params method returns a hash with string keys.
    # 2. When a query parameter without a value gets parsed by Addressable::URI, the value is set to nil.
    # 3. Because of 1., when #add_params merges the new params with the existing ones, instead of overwriting the nil
    #    value, it adds a new key-value pair to the resulting hash.
    # 4. When #add_params afterwards calls the Addressable::URI#query_values= method with the resulting hash, that
    #    method then converts the hash to an array of key-value pairs, converting the keys to strings in the process.
    #    After that it sorts the resulting array. Since sorting an array of arrays works by comparing the values of the
    #    inner arrays one by one, and since we've ended up with two key-value pairs with the same key, the sorting will
    #    proceed to the second element of the inner array. Because of 2. the value of the second element is nil for
    #    one of the key-value pairs, and the sorting will fail because nil is not comparable with a string.
    context 'when the the added params is similar to one already present in the URL, but which has no value' do

      let(:url_string) { 'http://example.com/path?appended' }

      it 'should overwrite the existing params' do
        expect(subject.query).to eql 'appended=param'
      end
    end
  end

  describe :remove_param do
    subject { url.remove_param('param1') }
    its(:query) { should eql 'param2=value2' }
  end

  describe :dup do
    subject { url.dup }
    it { should be_kind_of RackCAS::URL }
    its(:to_s) { should eql url.to_s }
    its(:to_hash) { should eql Addressable::URI.parse(url_string).to_hash }
  end
end