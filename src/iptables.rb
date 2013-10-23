#
# encoding utf-8
# Copyright(c) 2012-2013 ACCESS CO., LTD. All rights reserved.
#

class IpTables

  MAP = {
    input: 'i',
    output: 'o',
    src_addr: 's',
    dst_addr: 'd',
    src_port: 'sport',
    dst_port: 'dport',
    protocol: 'p'
  }

  def self.repository
    @repository ||= {}
  end

  def initialize(&block)
    @policy = []
    @chain  = []
    @scope  = {}
    instance_eval(&block) if block
  end

  def set_policy(options)
    if options == nil
      @policy = []
      return
    end
    @policy = options.each_with_object %w(-F) do |(chain, target), dst|
      dst << "-P #{chain.to_s.upcase} #{target.to_s.upcase}"
    end
    @policy
  end

  def scope(options, &block)
    backup = @scope
    @scope = @scope.merge(options)
    yield
    self
  ensure
    @scope = backup
  end

  def accept(options)
    append options.merge(target: 'ACCEPT')
  end

  def drop(options)
    append options.merge(target: 'DROP')
  end

  def append(options)
    options = @scope.merge options
    if (chain = options.delete :chain)
      buff = "-A #{chain.to_s.upcase}"
    else
      raise ArgumentError, 'option :chain must be specified'
    end
    options.each do |k, v|
      case k
      when *MAP.keys
        buff << " -" << MAP[k] << " " << v.to_s
      when :target
        buff << " -j " << v.to_s.upcase
      when :state
        buff << " -m state --state " << Array(v).join(',')
      else
        raise ArgumentError, "Unknown option '#{k}'"
      end
    end
    @chain << buff
  end

  def mixin(iptables)
    case iptables
    when self.class
      @policy = iptables.instance_variable_get(:@policy)
      iptables.instance_variable_get(:@chain).each do |chain|
        @chain << chain
      end
    when Symbol
      mixin self.class.repository.fetch(iptables)
    else
      raise ArgumentError, "Not support: #{iptables.inspect}"
    end
  end

  def write(out = $stdout)
    [@policy, @chain].each do |option_list|
      option_list.each do |option|
        out << 'iptables ' <<  option << "\n"
      end
    end
    out
  end
end

IpTables.repository[:minimal] = IpTables.new do
  set_policy input: 'DROP', output: 'DROP', forward: 'DROP'

  # to use 127.0.0.1
  accept chain: :input,   input: 'lo'
  accept chain: :output, output: 'lo'

  # support ping
  accept chain:  :input, protocol: 'icmp'
  accept chain: :output, protocol: 'icmp'
  
end

IpTables.repository[:default] = IpTables.new do
  set_policy input: 'DROP', output: 'ACCEPT', forward: 'DROP'

  scope chain: :input do
    accept state: %w(ESTABLISHED RELATED)

    scope src_addr: '192.168.0.0/16' do # accept local IP
      accept protocol: 'tcp'
      accept protocol: 'udp'
    end
    accept protocol: 'tcp', dst_port: 22 # SSH
  end
end
