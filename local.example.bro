@load base/frameworks/intel
@load ./dronebl-dnsbl

redef DroneBL::new_conn_check = T;
redef DroneBL::add_to_intel = T;
redef DroneBL::check_ipv6 = T;
