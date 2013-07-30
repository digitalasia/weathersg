Weather::Application.routes.draw do

  	root :to => "weather#index"

    resources :weather, :only => [:index] do

      get 'fetch', :on => :collection
      get 'today', :on => :collection #removed
      get 'three', :on => :collection
      get 'twofive', :on => :collection
      get 'nsewc', :on => :collection

      get 'north', :on => :collection
      get 'south', :on => :collection
      get 'east', :on => :collection
      get 'west', :on => :collection
      get 'central', :on => :collection
      get 'overall', :on => :collection

    end 
end
