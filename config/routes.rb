Rails.application.routes.draw do
  get '/', to: redirect('users/sign_in')

  devise_for :users, controllers: {
    sessions: 'users/sessions'
  }

  devise_scope :user do
    get 'signup', to: 'users/registrations#new'
    get 'login', to: 'users/sessions#new'
    get 'logout', to: 'users/sessions#destroy'
  end

  if Rails.env.development? || Rails.env.test?
    mount LetterOpenerWeb::Engine, at: '/letter_opener'
  end
end