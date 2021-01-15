class CreateSamlIdpConfigs < ActiveRecord::Migration[6.1]
  def change
    create_table :saml_idp_configs do |t|
      t.string :x509_certificate
      t.string :secret_key
      t.string :password
      t.string :algorithm
      t.string :organization_name
      t.string :organization_url
      t.string :base_saml_location
      t.string :entity_id
      t.string :reference_id_generator
      t.string :attribute_service_location
      t.string :single_service_post_location
      t.string :single_service_redirect_location
      t.string :single_logout_service_post_location
      t.string :single_logout_service_redirect_location
      t.string :attributes
      t.string :assertion_consumer_service_hosts
      t.string :session_expiry
      t.json :service_provider

      t.timestamps
    end
  end
end
