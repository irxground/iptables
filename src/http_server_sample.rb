require File.expand_path('../iptables', __FILE__)

IpTables.new do
  mixin :default
  scope chain: :input, protocol: 'tcp' do
    accept dst_port: 80
    accept dst_port: 22
  end
end.write
