@load base/frameworks/intel
@load base/bif/bro.bif
@load ./dronebl-dnsbl

redef DroneBL::new_conn_check = T;
redef DroneBL::add_to_intel = T;
redef DroneBL::check_ipv6 = T;

when (local threat_class = DroneBL::classify_ip(127.0.0.1))
	print fmt("%s ThreatClass is %s", 127.0.0.1, threat_class);

when(local is_drone = DroneBL::check_ip([::1])) {
	if(is_drone) {
		print fmt("%s is a DRONE /!\\", [::1]);
	} else {
		print fmt("%s is NOT a drone! :)", [::1]);
	}
}
