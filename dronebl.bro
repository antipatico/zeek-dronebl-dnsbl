# Author: antipatico (github.com/antipatico)
# Year: 2019
# License: VRLFSC (read the file LICENSE.txt)
@load base/bif/bro.bif
@load base/bif/strings.bif
@load base/bif/event.bif

module DroneBL;

export {
	redef enum Log::ID += { LOG };
	
	type Info: record {
		ip: addr &log;
	};

	## An enum representing the threat class of an entry in the DroneBL db.
	## Copied from here: https://dronebl[dot]org[slash]classes
	type ThreatClass: enum {
		## Not a threat.
		NONE,
		## Testing class.
		TESTING,
		## Sample data used for heruistical analysis.
		SAMPLE,
		## IRC spam drone (litmus/sdbot/fyle).
		IRC,
		## Bottler (experimental).
		BOTTLER,
		## Unknown worm or spambot.
		UNK_WORM_SPAMBOT,
		## DDoS drone.
		DDOS,
		## Open SOCKS proxy.
		SOCKS_PROXY,
		## Open HTTP proxy.
		HTTP_PROXY,
		## Proxychain.
		PROXYCHAIN,
		## Web Page Proxy.
		WEB_PROXY,
		## Open DNS Resolver.
		DNS_RESOLVER,
		## Automated dictionary attacks.
		DICTIONARY,
		## Open WINGATE proxy.
		WINGATE_PROXY,
		## Compromised router / gateway.
		ROUTER_GATEWAY,
		## Autorooting worms,
		AUTOROOTING_WORM,
		## Automatically determined botnet IPs (experimental)
		AUTO_BOTNET_ZOMBIE,
		## Possibly compromised DNS/MX type hostname detected on IRC.
		DNS_MX_HOSTNAME_IRC,
		## Abused VPN service.
		VPN,
		## Uncategorized threat class
		UNCATEGORIZED
	};

	## If true, check all new connections, using CheckIP.
	option new_conn_check : bool = F;	
	## If true, adds all the records found using DroneBL te the Intel
	## framework.
	option add_to_intel : bool = F;
	## Request timeout for queries to DroneBL db.
	option request_timeout : interval = 30sec;
	## Subnets (v4) to ignore while checking IPs.
	const intranet : set[subnet] = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } &redef;

	## Given a ThreatClass returns true if considered a Drone.
	global is_drone: function(tc: ThreatClass) : bool;
	## Function to check an IP(v4) address.
	global check_ip: function(ip: addr) : bool;
	## Returns the ThreatClass of an IP(v4) address.
	global threat_class_ip: function(ip: addr) : ThreatClass;

	global log_dronebl: event(rec: Info);
}

global dronebl_table : table[addr] of ThreatClass;

function classify_intel(ip:addr, tc:ThreatClass) {
	if(add_to_intel) {
		## TODO: this.
		print fmt("%s: %s", ip, tc);
	}
}

function build_dronebl_query(ip:addr) : string {
	local y : string_vec = split_string(cat(ip), /\./);
	return cat(y[3],".",y[2],".",y[1],".",y[0], ".dnsbl.dronebl.org");
}

function evaluate_return_code(code:count) : ThreatClass {
	switch code
	{
	case 0:
		return NONE; # This is because lookup_hostname returns 0.0.0.0 in case of no response.
	case 1:
		return TESTING;
	case 2:
		return SAMPLE;
	case 3:
		return IRC;
	case 5:
		return BOTTLER;
	case 6:
		return UNK_WORM_SPAMBOT;
	case 7:
		return DDOS;
	case 8:
		return SOCKS_PROXY;
	case 9:
		return HTTP_PROXY;
	case 10:
		return PROXYCHAIN;
	case 11:
		return WEB_PROXY;
	case 12:
		return DNS_RESOLVER;
	case 13:
		return DICTIONARY;
	case 14:
		return WINGATE_PROXY;
	case 15:
		return ROUTER_GATEWAY;
	case 16:
		return AUTOROOTING_WORM;
	case 17:
		return AUTO_BOTNET_ZOMBIE;
	case 18:
		return DNS_MX_HOSTNAME_IRC;
	case 19:
		return VPN;
	default:
		return UNCATEGORIZED;
	}
}

event bro_init() &priority=5
{
	Log::create_stream(LOG, [$columns=Info, $ev=log_dronebl, $path="dronebl"]);
}

event new_connection(c: connection) {
	local src = c$id$orig_h;
	local dest = c$id$resp_h;

	local to_check = [src,dest];

	for (ip in to_check) {
		when (new_conn_check && (local tc = threat_class_ip(ip)) && is_drone(tc)) {
			# TODO: log.
			classify_intel(ip, dronebl_table[ip]);
		}
	}
}

function is_drone(tc:ThreatClass) : bool {
	return tc != NONE && tc != TESTING && tc != SAMPLE;
}

function check_ip(ip:addr) : bool {
	if (!is_v4_addr(ip) || (ip in intranet)) {
		return F;
	}
	
	if (ip in dronebl_table) {
		return is_drone(dronebl_table[ip]);
	}

	return when (local tc = threat_class_ip(ip) ) {
		return is_drone(tc);
	} 
}

# FIXME: lookup_hostname doesn't stop zeek death. maybe open a bug report?
# FIXME: semaphore (via events maybe) to do a single request for every ip.
# FIXME: unify return statements.
function threat_class_ip(ip:addr) : ThreatClass {
	if (!is_v4_addr(ip) || (ip in intranet)) {
		return NONE;
	}
	
	if (ip in dronebl_table) {
		return dronebl_table[ip];
	}

	local query = build_dronebl_query(ip);
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
			dronebl_table[ip] = NONE;
			return dronebl_table[ip];
		}
		
		# get the result (last byte of the IP)
		tc_code = to_count(split_string(tc_record, /\./)[3]);
		
		dronebl_table[ip] = evaluate_return_code(tc_code);
		return dronebl_table[ip];
	}
	timeout request_timeout {
		return NONE;
	}
}
