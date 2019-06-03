# Author: antipatico (github.com/antipatico)
# Year: 2019
# License: VRLFSC (read the file LICENSE.txt)
@load base/bif/bro.bif
@load base/bif/strings.bif
@load base/bif/event.bif
@load base/bif/reporter.bif

module DroneBL;

export {
	redef enum Log::ID += { LOG };
	
	type Info: record {
		ip: addr &log;
	};

	## If true, check all new connections, using CheckIP.
	option new_conn_check : bool = F;	
	## If enabled, adds all the records found using DroneBL te the Intel
	## framework.
	option add_to_intel : bool = F;
	## Check for IPv4 entries
	option check_ipv4 : bool = T;
	## Check for IPv6 entries
	option check_ipv6 : bool = F;
	## Request timeout for queries to DroneBL db.
	option request_timeout : interval = 30sec;
	## Subnets (v4) to ignore while checking IPs.
	const intranet : set[subnet] = { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, [::1]/128, [FC00::]/7 } &redef;

	## Given a ThreatClass returns true if considered a Drone.
	global is_drone: function(tc: ThreatClass) : bool;
	## Function to check an IP(v4) address.
	global check_ip: function(ip: addr) : bool;
	## Returns the ThreatClass of an IP(v4) address.
	global classify_ip: function(ip: addr) : ThreatClass;

	global log_dronebl: event(rec: Info);
}

global dronebl_table : table[addr] of ThreatClass;

function classify_intel(ip:addr, tc:ThreatClass) {
	if(add_to_intel) {
		## TODO: this.
		print fmt("%s: %s", ip, tc);
	}
}


event bro_init() &priority=5
{
	Log::create_stream(LOG, [$columns=Info, $ev=log_dronebl, $path="dronebl"]);
}

event new_connection(c: connection) &priority=10 {
	local src = c$id$orig_h;
	local dest = c$id$resp_h;

	local to_check = [src,dest];

	for (ip in to_check) {
		when (new_conn_check && (local tc = classify_ip(ip)) && is_drone(tc)) {
			# TODO: log.
		}
	}
}

function is_drone(tc:ThreatClass) : bool {
	return tc != QUERYING && tc != NONE && tc != TESTING && tc != SAMPLE;
}

function check_ip(ip:addr) : bool {
	if (ip in dronebl_table) {
		return is_drone(dronebl_table[ip]);
	}

	return when (local tc = classify_ip(ip) ) {
		return is_drone(tc);
	} 
}

# FIXME: lookup_hostname doesn't stop zeek death. maybe open a bug report?
function classify_ip(ip:addr) : ThreatClass {
	local query : string;

	if ((ip in intranet) ||
	    (is_v4_addr(ip) && !check_ipv4) ||
	    (is_v6_addr(ip) && !check_ipv6)) {
		return NONE;
	}
	
	if (ip in dronebl_table) {
		return when (dronebl_table[ip] != QUERYING) {
			return dronebl_table[ip];
		}
	}
	
	dronebl_table[ip] = QUERYING;
	
	if(is_v4_addr(ip)) {
		query = build_dronebl_query_v4(ip);
	} else  {
		query = build_dronebl_query_v6(ip);
	}

	return when( local names = lookup_hostname(query) ) {
		local tc_record : string;
		local tc_code : count;
		
		# Special case, should never happen when using lookup_hostname
		if(|names| < 1) {
			dronebl_table[ip] = NONE;
			return dronebl_table[ip];
		}

		# since names is a set we must "loop" through it.
		for (arecord in names) {
			if(is_v4_addr(arecord)) {
				tc_record = cat(arecord);
				break;
			}
		}

		# Special case, should never happen.
		if (tc_record == "") {
			Reporter::fatal(fmt("Invalid response from the DNS server for ip address %s, expected an IPv4 response.", ip));
		}
		
		# get the result (last byte of the IP)
		tc_code = to_count(split_string(tc_record, /\./)[3]);
		
		local tc = evaluate_return_code(tc_code);
		if(add_to_intel && is_drone(tc)) {
			classify_intel(ip, tc);
		}
		dronebl_table[ip] = tc;
		return tc;
	}
	timeout request_timeout {
		return NONE;
	}
}
