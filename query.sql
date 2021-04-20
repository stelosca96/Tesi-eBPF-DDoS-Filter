create table flows
(
	ip_src INT UNSIGNED not null,
	ip_dst int UNSIGNED not null,
	port_dst SMALLINT UNSIGNED not null,
	timestamp timestamp not null,
	udp_tx int UNSIGNED not null,
	icmp_tx int UNSIGNED not null,
	packet_rate int UNSIGNED not null,
	throughput int UNSIGNED not null,
	udp_tx_53 int UNSIGNED not null,
	constraint flows_pk
		primary key (port_dst, ip_src, ip_dst, timestamp)
);

