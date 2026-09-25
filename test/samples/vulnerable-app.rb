# test/samples/vulnerable-app.rb
# Sample file with intentional Ruby vulnerabilities for testing Sentinel-VSC

require "sinatra"
require "active_record"

# ❌ VULNERABLE: Hardcoded credentials (auth-003)
DB_CONFIG = {
  "host" => "prod-db.internal.example.com",
  password: "SuperSecret123!",
  api_key: "sk-live-XXXXXXXXXXXXXXXX",
}

# ❌ VULNERABLE: SQL Injection — string interpolation in ActiveRecord (sqli-006)
get "/users" do
  name = params[:name]
  users = User.where("name = '#{name}'")
  users.to_json
end

# ❌ VULNERABLE: Command Injection — system() with interpolation (cmdi-003)
post "/convert" do
  filename = params[:filename]
  system("convert #{filename} -resize 200x200 output.jpg")
  "Done"
end

# ❌ VULNERABLE: XSS — raw() with user input (xss-005)
get "/profile" do
  @comment = params[:comment]
  raw(params[:comment])
end

# ❌ VULNERABLE: XSS — html_safe on user input (xss-005)
get "/bio" do
  user_input = params[:bio]
  raw(@user_input)
end
