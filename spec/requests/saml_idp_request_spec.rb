require 'rails_helper'

RSpec.describe 'SamlIdps', type: :request do
  include SamlSpecHelper

  let(:good_user) { create(:user, :confirmed) }
  let(:bad_user) { create(:user, :confirmed) }
  let(:pv_key) { generate_pv_key }
  let(:saml_cert) { issue_cert(pv_key,) }

  describe 'IdP response' do
    let!(:idp_config) { create(:saml_idp_config) }
    let(:idp_entity_id) { URI.join(Rails.application.secrets.base_url, 'idp/', "#{idp_setting.id}/", 'saml').to_s }
    let!(:saml_sp_config) do
      setting = OneLogin::RubySaml::Settings.new
      sp_metadata_conf = idp_config.sp_metadata

      # When disabled, saml validation errors will raise an exception.
      setting.soft = true
      # SP section
      setting.issuer                         = sp_metadata_conf[:entity_id]
      setting.assertion_consumer_service_url = sp_metadata_conf[:assertion_consumer_service_hosts].first['location']
      setting.assertion_consumer_logout_service_url = ''

      # Idp setting
      setting.idp_entity_id                  = idp_entity_id
      setting.idp_sso_target_url             = URI.join(idp_entity_id, '/auth').to_s
      setting.idp_slo_target_url             = URI.join(idp_entity_id, '/logout').to_s
      setting.idp_cert                       = idp_config.certificate

      setting.name_identifier_format         = idp_config.sp_metadata[:name_id_formats].first

      # Security section
      setting.security[:authn_requests_signed] = false
      setting.security[:logout_requests_signed] = false
      setting.security[:logout_responses_signed] = false
      setting.security[:metadata_signed] = false
      setting.security[:digest_method] = XMLSecurity::Document::SHA1
      setting.security[:signature_method] = XMLSecurity::Document::RSA_SHA1

      setting
    end
    let(:test_setting) { idp_setting.id }

    subject do
      get saml_auth_url, params: {
        SAMLRequest: authn_request,
        RelayState: 'http://fallback.com'
      }
    end

    context 'when authn_request come before signed in' do
      let(:authn_request) do
        config = OneLogin::RubySaml::Authrequest.new.create(saml_sp_config)
        CGI.unescape(config.split('=').last)
      end
      let(:sp_acs_url) { idp_config.parsed_metadata['assertion_consumer_service_hosts'].first['location'] }

      before do
        # RSpec request test needs to be call logout for clean session
        post users_sign_out_url
        is_expected.to redirect_to(new_user_session_url)
        post response.location, params: {
          user: {
            email: good_user.email,
            password: good_user.password
          }
        }
      end

      it 'will redirect back to origin request' do
        expect(response).to have_http_status(:redirect)
        expect { URI.parse(response.location) }.not_to raise_error
        expect(URI.parse(response.location).path).to eq(saml_auth_path)
        expect(URI.decode_www_form(URI.parse(response.location).query).to_h)
          .to include('RelayState' => 'http://fallback.com', 'SAMLRequest' => authn_request)

        get saml_auth_url, params: {
          SAMLRequest: authn_request,
          RelayState: 'http://fallback.com'
        }

        expect(response).to render_template('idp/saml_idp/new')
      end

      it 'will render auto submit form with metadata acs url' do
        post saml_auth_url, params: {
          SAMLRequest: authn_request,
          RelayState: 'http://fallback.com'
        }

        expect(response.body).to include("form action=\"#{sp_acs_url}\"")
      end
    end

    context 'when authn_request come after time out' do
      let(:authn_request) do
        config = OneLogin::RubySaml::Authrequest.new.create(saml_sp_config)
        CGI.unescape(config.split('=').last)
      end

      it 'will redirect back to origin request' do
        is_expected.to redirect_to(new_user_session_url)
        post response.location, params: {
          user: {
            email: good_user.email,
            password: good_user.password
          }
        }
        expect(response).to have_http_status(:redirect)
        expect { URI.parse(response.location) }.not_to raise_error
        expect(URI.parse(response.location).path).to eq(auth_idp_saml_path(test_setting))
        expect(URI.decode_www_form(URI.parse(response.location).query).to_h)
          .to include('RelayState' => 'http://fallback.com', 'SAMLRequest' => authn_request)
      end
    end

    context 'when auth_request without ACS url' do
      let(:sp_acs_url) { idp_config.parsed_metadata['assertion_consumer_service_hosts'].first['location'] }

      let(:authn_request_no_acs) do
        config = saml_sp_config
        config.assertion_consumer_service_url = nil
        request = OneLogin::RubySaml::Authrequest.new.create(config)
        CGI.unescape(request.split('=').last)
      end

      before do
        post new_user_session_url, params: {
          user: {
            email: good_user.email,
            password: good_user.password
          }
        }
      end

      it 'will render response view without error' do
        get saml_auth_url, params: {
          SAMLRequest: authn_request_no_acs,
          RelayState: 'http://fallback.com'
        }

        expect(response).to render_template('idp/saml_idp/new')
      end

      it 'will render response auto submit form with metadata acs url' do
        post saml_auth_url, params: {
          SAMLRequest: authn_request_no_acs,
          RelayState: 'http://fallback.com'
        }

        expect(response.body).to include("form action=\"#{sp_acs_url}\"")
      end
    end
  end

  describe 'Encrypted IdP Response' do
    let!(:idp_config) do
      create(:saml_idp_config, raw_metadata: load_test_metadata('metadata_with_enc_key.xml'), parsed_metadata: nil)
    end
    let(:idp_entity_id) { URI.join(Rails.application.secrets.base_url, 'idp/', "#{idp_setting.id}/", 'saml').to_s }
    let!(:saml_sp_config) do
      setting = OneLogin::RubySaml::Settings.new
      sp_metadata_conf = idp_config.sp_metadata

      # When disabled, saml validation errors will raise an exception.
      setting.soft = true
      # SP section
      setting.issuer                         = sp_metadata_conf[:entity_id]
      setting.assertion_consumer_service_url = sp_metadata_conf[:assertion_consumer_service_hosts].first['location']
      setting.assertion_consumer_logout_service_url = ''
      setting.private_key = pv_key
      setting.certificate = saml_cert

      # Idp setting
      setting.idp_entity_id                  = idp_entity_id
      setting.idp_sso_target_url             = URI.join(idp_entity_id, '/auth').to_s
      setting.idp_slo_target_url             = URI.join(idp_entity_id, '/logout').to_s
      setting.idp_cert                       = idp_config.certificate
      cert = OpenSSL::X509::Certificate.new(idp_config.certificate)
      setting.idp_cert_fingerprint = Digest::SHA1.hexdigest(cert.to_der).scan(/../).join(':')

      setting.name_identifier_format = idp_config.sp_metadata[:name_id_formats].first

      # Security section
      setting.security[:authn_requests_signed] = false
      setting.security[:logout_requests_signed] = false
      setting.security[:logout_responses_signed] = false
      setting.security[:metadata_signed] = false
      setting.security[:digest_method] = XMLSecurity::Document::SHA1
      setting.security[:signature_method] = XMLSecurity::Document::RSA_SHA1

      setting
    end

    context 'when raw metadata have encryption key' do
      let(:sp_setting) do
        { settings: saml_sp_config, skip_subject_confirmation: true }
      end

      before do
        idp_setting.update_attributes(url: idp_entity_id)
        post new_user_session_url, params: {
          user: {
            email: good_user.email,
            password: good_user.password
          }
        }
      end

      it 'will create a valid signed and encrypted assertion in response' do
        post auth_idp_saml_url(group.name, idp_setting), params: {
          SAMLRequest: '',
          RelayState: ''
        }
        saml_response = Nokogiri::HTML(response.body).at('input[@name=SAMLResponse]')['value']
        saml_response = OneLogin::RubySaml::Response.new(saml_response, sp_setting)
        assert saml_response.decrypted_document
        expect(saml_response.is_valid?).to be_truthy
      end
    end
  end

  describe 'Signed AuthnRequest' do
    let!(:idp_config) do
      create(:saml_idp_config, raw_metadata: load_test_metadata('metadata_signed_authn_req.xml'), parsed_metadata: nil)
    end
    let(:idp_entity_id) do
      URI.join(Rails.application.secrets.base_url, "#{group.name}/", 'idp/', "#{idp_setting.id}/", 'saml').to_s
    end
    let(:sp_settings) do
      setting = OneLogin::RubySaml::Settings.new
      # When disable, saml validation errors will raise an exception.
      setting.soft = false
      sp_metadata_conf = idp_config.sp_metadata
      # SP settings
      setting.issuer                         = sp_metadata_conf[:entity_id]
      setting.assertion_consumer_service_url = sp_metadata_conf[:assertion_consumer_service_hosts].first['location']
      setting.assertion_consumer_logout_service_url = ''
      setting.private_key = pv_key
      setting.certificate = saml_cert

      # Idp settings
      setting.idp_entity_id                  = idp_entity_id
      setting.idp_sso_target_url             = URI.join(idp_entity_id, '/auth').to_s
      setting.idp_slo_target_url             = URI.join(idp_entity_id, '/logout').to_s
      setting.idp_cert                       = idp_config.certificate
      cert = OpenSSL::X509::Certificate.new(idp_config.certificate)
      setting.idp_cert_fingerprint = Digest::SHA1.hexdigest(cert.to_der).scan(/../).join(':')

      # Security section
      # Signed embedded singature
      setting.security[:authn_requests_signed] = true
      setting.security[:embed_sign] = true
      setting.security[:logout_requests_signed] = false
      setting.security[:logout_responses_signed] = false
      setting.security[:metadata_signed] = true
      setting.security[:digest_method] = XMLSecurity::Document::SHA256
      setting.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
      setting
    end

    before do
      # Make it as idp initiated saml setting
      idp_setting.update_attributes(url: idp_entity_id)
    end

    # let(:saml_message) { OneLogin::RubySaml::SamlMessage.new }
    # let(:raw_signed_request) { File.read(Rails.root.join('spec/fixtures/idp/cert/x509cert.crt')) }

    context 'when a valid signed request come' do
      # let(:encoded_authn_req) { saml_message.send(:encode_raw_saml, raw_signed_request, sp_settings) }

      let(:authn_request) do
        config = OneLogin::RubySaml::Authrequest.new.create(sp_settings)
        CGI.unescape(config.split('=').last)
      end

      before do
        post new_user_session_url, params: {
          user: {
            email: good_user.email,
            password: good_user.password
          }
        }
      end

      it 'will successfully process response' do
        post auth_idp_saml_url(group.name, idp_setting.id), params: {
          SAMLRequest: authn_request,
          RelayState: 'http://example.com/home'
        }
        expect(response).to have_http_status(:success)
        assert(Nokogiri::HTML(response.body).at('input[@name=SAMLResponse]')['value'])
      end
    end
  end

  def load_test_metadata(metadata_name)
    File.read(Rails.root.join('spec/fixtures/idp/saml/' + metadata_name))
  end
end
