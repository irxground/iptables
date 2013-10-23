require File.expand_path('../../src/iptables', __FILE__)

describe IpTables do
  describe '#write' do
    specify { IpTables.new.write("").should == '' }
  end

  describe '#set_policy' do
    specify 'No policy' do
      IpTables.new {}.should write []
    end

    it 'shoud not write any' do
      IpTables.new {
        set_policy nil
      }.should write []
    end

    it 'should reset' do
      IpTables.new {
        set_policy({})
      }.should write [
        'iptables -F'
      ]
    end

    it 'should write each options' do
      IpTables.new {
        set_policy input: 'DROP', forward: 'DROP', output: 'ACCEPT'
      }.should write [
        'iptables -F',
        'iptables -P INPUT DROP',
        'iptables -P FORWARD DROP',
        'iptables -P OUTPUT ACCEPT'
      ]
    end

    it 'should override policy' do
      IpTables.new {
        set_policy input: 'DROP', forward: 'DROP', output: 'ACCEPT'
        set_policy input: 'ACCEPT'
      }.should write [
        'iptables -F',
        'iptables -P INPUT ACCEPT',
      ]
    end
  end

  describe '#accept' do
    it 'support :state' do
      IpTables.new {
        accept chain: :input, state: %w(ESTABLISHED RELATED)
      }.should write [
        'iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT'
      ]
    end

    it 'support :protocol' do
      IpTables.new {
        accept chain: :input, protocol: 'icmp'
      }.should write [
        'iptables -A INPUT -p icmp -j ACCEPT'
      ]
    end

    it 'support :port' do
      IpTables.new {
        accept chain: :input, protocol: 'tcp', port: 80
      }.should write [
        'iptables -A INPUT -p tcp -dport 80 -j ACCEPT'
      ]
    end

    it 'support :target' do
      IpTables.new {
        accept chain: :input, protocol: 'tcp', source: '192.168.0.0/16'
      }.should write [
        'iptables -A INPUT -p tcp -s 192.168.0.0/16 -j ACCEPT'
      ]
    end

    it 'should not support unknown option' do
      expect {
        IpTables.new {
          accept unknown: 'true'
        }
      }.to raise_error(ArgumentError)
    end
  end

  describe '#append' do
    specify do
      expect {
        IpTables.new { append(port: 80) }
      }.to raise_error(ArgumentError)

      expect {
        IpTables.new { append(chain: 'INPUT', port: 80) }
      }.not_to raise_error
    end
  end

  describe '#scope' do
    it 'support nested option' do
      IpTables.new {
        scope chain: :input do
          accept protocol: 'icmp'
          scope protocol: 'tcp' do
            accept port: 22
            accept port: 80
          end
        end
      }.should write [
        'iptables -A INPUT -p icmp -j ACCEPT',
        'iptables -A INPUT -p tcp -dport 22 -j ACCEPT',
        'iptables -A INPUT -p tcp -dport 80 -j ACCEPT'
      ]
    end
  end

  describe '#mixin' do
    it 'should override policy' do
      base = IpTables.new { set_policy input: 'ACCEPT' }
      IpTables.new {
        set_policy output: 'ACCEPT'
        mixin base
      }.should write [
        'iptables -F',
        'iptables -P INPUT ACCEPT'
      ]
      IpTables.new {
        mixin base
        set_policy output: 'ACCEPT'
      }.should write [
        'iptables -F',
        'iptables -P OUTPUT ACCEPT'
      ]
    end

    it 'should append chain' do
      base = IpTables.new { accept chain: :input, protocol: 'icmp' }
      IpTables.new {
        mixin base
        accept chain: :input, protocol: 'tcp', port: 80
      }.should write [
        'iptables -A INPUT -p icmp -j ACCEPT',
        'iptables -A INPUT -p tcp -dport 80 -j ACCEPT'
      ]
      IpTables.new {
        accept chain: :input, protocol: 'tcp', port: 80
        mixin base
      }.should write [
        'iptables -A INPUT -p tcp -dport 80 -j ACCEPT',
        'iptables -A INPUT -p icmp -j ACCEPT'
      ]
    end

    describe '.repository' do
      around(:each){ |example| backup_repository(&example) }

      it 'mixin from repository' do
        IpTables.repository[:rep_key] = IpTables.new do
          accept chain: :input, protocol: 'icmp'
        end
        IpTables.new {
          mixin :rep_key
          accept chain: :input, protocol: 'tcp', port: 80
        }.should write [
          'iptables -A INPUT -p icmp -j ACCEPT',
          'iptables -A INPUT -p tcp -dport 80 -j ACCEPT'
        ]
      end

      def backup_repository
        backup = IpTables.repository
        yield
      ensure
        IpTables.repository.clear.merge! backup
      end
    end
  end
end

RSpec::Matchers.define :write do |expect|
  match do |actual|
    check_error(actual, expect) == nil
  end

  failure_message_for_should do |actual|
    check_error(actual, expect)
  end

  def check_error(actual, expect)
    lines = actual.write("").each_line.to_a.map(&:strip)

    return "expect #{expect.size} lines, but was #{lines.size} line." if
      lines.size != expect.size

    lines.zip(expect).each_with_index do |(act, exp), ix|
      return "index #{ix}:\n  expect  #{exp.inspect}\n  but was #{act.inspect}" if
        act != exp
    end
    return nil
  end
end
