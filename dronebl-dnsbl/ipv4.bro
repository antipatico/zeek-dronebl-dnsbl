# Author: antipatico (github.com/antipatico)
# Year: 2019
# License: VRLFSC (read the file LICENSE.txt)
@load base/bif/strings.bif
@load ./common.bro

module DroneBL;

function build_dronebl_query_v4(ip:addr) : string {
	# FIXME: check if ipv4
	local y : string_vec = split_string(cat(ip), /\./);
	return cat(y[3],".",y[2],".",y[1],".",y[0], ".", dnsbl_domain);
}
