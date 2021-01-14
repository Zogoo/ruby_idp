Rails.application.routes.draw do
  get '/', to: redirect('/users/sign_in')

  devise_for :users, controllers: {
    sessions: 'users/sessions'
  }
end
