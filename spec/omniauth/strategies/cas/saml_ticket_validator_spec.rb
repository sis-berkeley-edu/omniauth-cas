require 'spec_helper'

describe OmniAuth::Strategies::CAS::SamlTicketValidator do
  let(:strategy) do
    double('strategy',
      service_validate_url: 'https://example.org/serviceValidate'
    )
  end
  let(:provider_options) do
    double('provider_options',
      disable_ssl_verification?: false,
      merge_multivalued_attributes: false,
      ca_path: '/etc/ssl/certsZOMG'
    )
  end
  let(:validator) do
    OmniAuth::Strategies::CAS::SamlTicketValidator.new( strategy, provider_options, '/foo', nil )
  end

  describe '#call' do
    before do
      stub_request(:post, 'https://example.org/serviceValidate?')
        .to_return(status: 200, body: '')
    end

    subject { validator.call }

    it 'returns itself' do
      expect(subject).to eq validator
    end

    it 'uses the configured CA path' do
      subject
      expect(provider_options).to have_received :ca_path
    end
  end

  describe 'called instances' do
    let(:ok_fixture) do
      File.expand_path(File.join(File.dirname(__FILE__), '../../../fixtures/berkeley_cas_success.xml'))
    end
    let(:service_response) { File.read(ok_fixture) }

    describe '#success_body' do
      before do
        stub_request(:post, 'https://example.org/serviceValidate?')
          .to_return(status: 200, body: service_response)
        validator.call
      end

      subject { validator.success_body }

      it 'provides status code' do
        expect(subject).to be_an_instance_of Nokogiri::XML::NodeSet
        expect(subject.first).to be_an_instance_of Nokogiri::XML::Element
        expect(subject.first['Value']).to eq 'saml1p:Success'
      end
    end

    describe '#user_info' do
      before do
        stub_request(:post, 'https://example.org/serviceValidate?')
          .to_return(status: 200, body: service_response)
        validator.call
      end

      subject { validator.user_info }

      context 'with default settings' do
        it 'parses user info from the response' do
          expect(subject).to include 'authenticationDate' => '2023-11-17T21:56:19.066445Z'
          expect(subject).to include 'authenticationMethod' => 'Static Credentials'
          expect(subject).to include 'clientIpAddress' => '192.168.0.5'
          expect(subject).to include 'credentialType' => 'UsernamePasswordCredential'
          expect(subject).to include 'isFromNewLogin' => 'true'
          expect(subject).to include 'longTermAuthenticationRequestTokenUsed' => 'false'
          expect(subject).to include 'nameIdentifier' => '1044957'
          expect(subject).to include 'samlAuthenticationStatementAuthMethod' => 'urn:oasis:names:tc:SAML:1.0:am:password'
          expect(subject).to include 'serverIpAddress' => '192.168.0.45'
          expect(subject).to include 'successfulAuthenticationHandlers' => 'Static Credentials'
          expect(subject).to include 'user' => nil
          expect(subject).to include 'userAgent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
        end
      end

      context 'when merging multivalued attributes' do
        let(:provider_options) do
          double('provider_options',
            disable_ssl_verification?: false,
            merge_multivalued_attributes: true,
            ca_path: '/etc/ssl/certsZOMG'
          )
        end

        it 'parses multivalued user info from the response' do
          expect(subject).to include 'authenticationDate' => '2023-11-17T21:56:19.066445Z'
          expect(subject).to include 'authenticationMethod' => 'Static Credentials'
          expect(subject).to include 'clientIpAddress' => '192.168.0.5'
          expect(subject).to include 'credentialType' => 'UsernamePasswordCredential'
          expect(subject).to include 'isFromNewLogin' => 'true'
          expect(subject).to include 'longTermAuthenticationRequestTokenUsed' => 'false'
          expect(subject).to include 'nameIdentifier' => '1044957'
          expect(subject).to include 'samlAuthenticationStatementAuthMethod' => 'urn:oasis:names:tc:SAML:1.0:am:password'
          expect(subject).to include 'serverIpAddress' => '192.168.0.45'
          expect(subject).to include 'successfulAuthenticationHandlers' => 'Static Credentials'
          expect(subject).to include 'user' => nil
          expect(subject).to include 'userAgent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
        end
      end
    end
  end

end
