class SamlIdpController < ApplicationController
  include SamlIdp::Controller

  def new; end

  def show
    send_data SamlIdp.metadata.signed,
              type: 'application/octet-stream',
              filename: 'idp-metadata.xml',
              disposition: 'inline'
  end

  def create
    @saml_response = idp_make_saml_response
    render action: :create, layout: false
  end

  def logout
    @saml_response = idp_make_saml_response
    current_user.logout
    render action: :create, layout: false
  end

  def idp_make_saml_response
    # NOTE: encryption is optional
    encode_response current_user, encryption: {
      cert: nil,
      block_encryption: 'aes256-cbc',
      key_transport: 'rsa-oaep-mgf1p'
    }
  end
  protected :idp_make_saml_response
end
