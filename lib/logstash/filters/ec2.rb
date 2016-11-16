# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "logstash/plugin_mixins/aws_config"
require "lru_redux"


class LogStash::Filters::Ec2 < LogStash::Filters::Base
  include LogStash::PluginMixins::AwsConfig::V2

  InstanceNotFoundError = Class.new RuntimeError

  config_name "ec2"

  # The source field to parse
  config :source, :validate => :string

  # The target field to place all the data
  config :target, :validate => :string, :default => "ec2"

  # The query used in describe instances
  config :query_name, :validate => :string, :default => "private-ip-address"

  # calls will be wrapped in a timeout instance
  config :timeout, :validate => :number, :default => 3

  # number of times to retry a failed resolve/reverse
  config :max_retries, :validate => :number, :default => 3

  # set the size of cache for successful requests
  config :hit_cache_size, :validate => :number, :default => 1000

  # how long to cache successful requests (in seconds)
  config :hit_cache_ttl, :validate => :number, :default => 300

  # cache size for failed requests (Resolv::
  config :failed_cache_size, :validate => :number, :default => 1000

  # how long to cache failed requests (in seconds)
  config :failed_cache_ttl, :validate => :number, :default => 5

  def register
    require "aws-sdk"

    # Jruby issue: https://github.com/jruby/jruby/issues/3645
    unless ::Aws.const_defined?("JRUBY_ISSUE_3646")
      ::Aws.const_set(:EC2, ::Aws::EC2)
      ::Aws.const_set(:JRUBY_ISSUE_3646, true)
    end

    # Aws SDK issue: https://github.com/aws/aws-sdk-ruby/issues/1135
    Aws::Xml::Parser.engine

    @hit_cache    = ::LruRedux::ThreadSafeCache.new(@hit_cache_size, @hit_cache_ttl)
    @failed_cache = ::LruRedux::ThreadSafeCache.new(@failed_cache_size, @failed_cache_ttl)

    @logger.info("Registering ec2 filter", :region => @region)

    @ec2   = ::Aws::EC2::Client.new(aws_options_hash)
  end

  def filter(event)
    return if resolve(event).nil?
    filter_matched(event)
  end

  private

  def resolve(event)
    ip = event.get(@source)

    begin
      return if ip.nil?
      return if @failed_cache[ip]

      info = @hit_cache.getset(ip) { retriable_get_instance(ip) }
      event.set(@target, info)
    rescue InstanceNotFoundError, Aws::EC2::Errors::ServiceError, Timeout::Error => e
      @failed_cache[ip] = true
      @logger.info("EC2: #{e.class} - #{e.message}", :field => @source, :value => ip)
      return
    end
  end

  private
  def retriable_get_instance(ip)
    query    = [{name: @query_name, values: [ip]}]
    reply    = retriable_request { @ec2.describe_instances(filters: query) }
    instance = reply.reservations.flat_map(&:instances).first

    instance || instance_not_found(query)

    info     = {
      "id"                => instance.instance_id,
      "image"             => instance.image_id,
      "instance_type"     => instance.instance_type,
      "availability_zone" => instance.placement.availability_zone,
      "security_groups"   => instance.security_groups.map(&:group_id)
    }
    tags = instance.tags.inject({}){|memo, t| memo.merge(t.key.downcase => t.value) }
    info.merge!(tags)
  end

  private
  def instance_not_found(query)
    raise InstanceNotFoundError.new("Instance with query=#{query.inspect} was not found.")
  end

  private
  def retriable_request(&block)
    tries = 0
    begin
      Timeout::timeout(@timeout) do
        block.call
      end
    rescue Timeout::Error
      if tries < @max_retries
        tries = tries + 1
        retry
      else
        raise
      end
    end
  end
end # class LogStash::Filters::Ec2
