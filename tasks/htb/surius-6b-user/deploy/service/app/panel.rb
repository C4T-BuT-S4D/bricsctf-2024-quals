# myapp.rb
require 'sinatra'
require "sinatra/basic_auth"

# Specify your authorization logic
authorize do |username, password|
    username == "ozon1337games" && password == "0zOnT3rP3lUNamV3l3l"
end

protect do
    get "/admin" do
      erb :admin
    end
end

protect do
    post "/admin" do
        post_param = params[:fname]
        post_param.delete! '/'
        file = open(post_param)
        file_data = file.read(1024 * 10)
        file.close
        file_data
    end
end

get '/user/:name' do
    Dir.entries('./public/user/'+params['name']).map { |e| "<p>#{e}</p>" }
end

get '/' do
    erb :index
end