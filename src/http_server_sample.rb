require File.expand_path('../iptables', __FILE__)

IpTables.new do
  mixin :default
  scope chain: :input, protocol: 'tcp' do
    accept port: 80
    accept port: 443
  end
end.write
