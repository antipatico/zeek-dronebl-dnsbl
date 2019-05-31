# Author: antipatico (github.com/antipatico)
# Year: 2019
# License: VRLFSC (read the file LICENSE.txt)
module DroneBL;

export {
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
