# Author: antipatico (github.com/antipatico)
# Year: 2019
# License: VRLFSC (read the file LICENSE.txt)
module DroneBL;

const dnsbl_domain = "dnsbl.dronebl.org";

## Since the builtin implementation is broken, I'm writing my own
function string_fill(len: int, source: string) : string {
	local ret : string = "";
	while(|ret|+|source|<=len) {
		ret = cat(ret,source);
	}
	return ret;
}

function zeropad(source:string, len:count) : string {
	return cat(string_fill(len-|source|, "0"), source);
}
