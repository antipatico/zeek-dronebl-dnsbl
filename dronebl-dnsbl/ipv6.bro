# Author: antipatico (github.com/antipatico)
# Year: 2019
# License: VRLFSC (read the file LICENSE.txt)
@load ./common.bro
@load base/bif/bro.bif
@load base/bif/strings.bif

module DroneBL;

function expand_ipv6(ip:addr) : string {
	if (!is_v6_addr(ip)) {
		return ""; #FIXME: throw an error.
	}

	# 1. ensure there are 8 hextets
	local xpnd = cat(ip);
	local hextets = split_string(xpnd, /:/);
	if(|hextets| < 8) {
		# 1.1 if not add them.
		local j = strstr(xpnd, "::"); # there must be
		local missing = string_fill(8-|hextets|, ":");
		xpnd = cat(sub_bytes(xpnd,0,j),missing,sub_bytes(xpnd,j,|xpnd|-j+1));
		hextets = split_string(xpnd, /:/);
	}
	# 2. expand it (zeropad)
	for (i in hextets) {
		hextets[i] = zeropad(hextets[i], 4);
	}
	# 3. join the expanded hextets
	return join_string_vec(hextets, ":");
}

function build_dronebl_query_v6(ip:addr) : string {
	if (!is_v6_addr(ip)) {
		return ""; #FIXME: throw an error.
	}
	#1. Expand the ipv6
	#   E.G. 1337:::::::6969 -> 1337:0000:0000:0000:0000:0000:0000:6969
	local query = expand_ipv6(ip);
	#2. Remove the ":"s
	#   E.G. 1337000000000000000000000000006969
	query = gsub(query, /:/, "");
	#3. Invert the digits
	#   E.G. 9696000000000000000000000000007331
	query = reverse(query);
	#4. Add a dot in between every digit
	#   E.G. 9.6.9.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.3.3.1
	local dots = "";
	for (i in query) {
		dots = cat(dots,i, ".");
	}
	query = sub_bytes(dots, 0, |dots|-1);
	#5. append the hostname (e.g. ".dnsbl.dronebl.org")
	#   E.G. 9.6.9.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.3.3.1.dnsbl.dronebl.org
	query = cat(query, ".", dnsbl_domain);
	return query;
}
