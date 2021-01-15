# frozen_string_literal: true

module SamlSpecHelper
  # This configuration related with fixtures/saml/certificates
  def example_saml_config
    settings = OneLogin::RubySaml::Settings.new

    # When disabled, saml validation errors will raise an exception.
    settings.soft = true

    # SP section
    settings.issuer                         = 'http://sp.example.com/demo1/metadata.php'
    settings.assertion_consumer_service_url = 'http://sp.example.com/demo1/index.php?acs'
    settings.assertion_consumer_logout_service_url = 'http://sp.example.com/demo1/logout'

    # IdP section
    settings.idp_entity_id                  = 'http://idp.example.com/metadata.php'
    settings.idp_sso_target_url             = 'http://idp.example.com/metadata.php'
    settings.idp_slo_target_url             = 'http://idp.example.com/sso/logout'
    settings.idp_cert                       = issue_cert(nil)

    settings.name_identifier_format         = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'

    # Security section
    settings.security[:authn_requests_signed] = false
    settings.security[:logout_requests_signed] = false
    settings.security[:logout_responses_signed] = false
    settings.security[:metadata_signed] = false
    settings.security[:digest_method] = XMLSecurity::Document::SHA1
    settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1

    settings
  end

  # Load and validate sample xml file
  def load_xml(sub_path)
    fixture_path = Rails.root.join("spec/fixtures/saml/#{sub_path}")
    doc = File.open(fixture_path) { |f| Nokogiri::XML(f) }
    doc.to_xml
  end

  # Deflate with Zlib and encode64
  def deflated_data(data)
    deflated = Zlib::Deflate.deflate(data, 9)[2..-5]
    Base64.encode64(deflated)
  end

  # Will sign SAML data which is didn't signed yet
  # ds:Signature data should not exist in your sample xml
  def sign_document(sub_path)
    ruby_saml_key_text = generate_pv_key
    ruby_saml_cert_text = issue_cert(ruby_saml_key_text)
    document = XMLSecurity::Document.new(load_xml(sub_path))
    formatted_cert = OneLogin::RubySaml::Utils.format_cert(ruby_saml_cert_text)
    cert = OpenSSL::X509::Certificate.new(formatted_cert)

    formatted_private_key = OneLogin::RubySaml::Utils.format_private_key(ruby_saml_key_text)
    private_key = OpenSSL::PKey::RSA.new(formatted_private_key)
    document.sign_document(private_key, cert)
  end

  # OpenSSL command helper
  def generate_pv_key
    OpenSSL::Random.seed(File.read('/dev/random', 16))
    rsa = OpenSSL::PKey::RSA.generate(1024)
    rsa.export(OpenSSL::Cipher.new('aes256'), 'secret!')
  end

  def issue_cert(key, issuer: nil, issuer_key: nil, not_before: nil, not_after: nil, digest: 'sha256')
    key ||= generate_pv_key
    issuer ||= cert
    issuer_key ||= key
    serial = rand(1..1000)
    cert_subj = OpenSSL::X509::Name.parse('/C=MN/ST=UB/L=CHD/O=Dummy Corp')
    extensions = [
      ['basicConstraints', 'CA:TRUE', true],
      ['keyUsage', 'cRLSign,keyCertSign', true]
    ]
    cert = generate_cert(cert_subj, key, serial, issuer,
                         not_before: not_before, not_after: not_after)
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = issuer
    extensions.each do |oid, value, critical|
      cert.add_extension(ef.create_extension(oid, value, critical))
    end
    cert.sign(issuer_key, digest)
    cert
  end

  def generate_cert(cert_subj, key, serial, issuer, not_before: nil, not_after: nil)
    cert = OpenSSL::X509::Certificate.new
    issuer ||= cert
    cert.version = 2
    cert.serial = serial
    cert.subject = cert_subj
    cert.issuer = issuer.subject
    cert.public_key = key
    now = Time.now
    cert.not_before = not_before || now - 3600
    cert.not_after = not_after || now + 3600
    cert
  end
end
