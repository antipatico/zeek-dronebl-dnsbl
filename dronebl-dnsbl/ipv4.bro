# Author: antipatico (github.com/antipatico)
# Year: 2019
# License: VRLFSC (read the file LICENSE.txt)
@load ./common.bro
@load base/bif/bro.bif
@load base/bif/strings.bif
@load base/bif/reporter.bif

module DroneBL;

function build_dronebl_query_v4(ip:addr) : string {
	if (!is_v4_addr(ip)) {
		Reporter::error(fmt("Can't build IPv4 DroneBL-DNSBL query: '%s' is not an IPv4 address.", ip));
		return "";
	}
	local y : string_vec = split_string(cat(ip), /\./);
	return cat(y[3],".",y[2],".",y[1],".",y[0], ".", dnsbl_domain);
}
