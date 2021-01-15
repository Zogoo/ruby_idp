Rails.application.routes.draw do
  get '/', to: redirect('/users/sign_in')

  devise_for :users, controllers: {
    sessions: 'users/sessions'
  }

  # Endpoints for SAML IdP feature
  get '/saml/metadata' => 'saml_idp#show'
  get '/saml/auth' => 'saml_idp#new'
  post '/saml/auth' => 'saml_idp#create'
  match '/saml/logout' => 'saml_idp#logout', via: [:get, :post, :delete]
end
