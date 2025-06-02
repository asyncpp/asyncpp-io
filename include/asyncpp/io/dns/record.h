#pragma once
#include <asyncpp/io/dns/enums.h>
#include <asyncpp/io/dns/qname.h>
#include <asyncpp/io/address.h>

#include <chrono>

namespace asyncpp::io::dns {
	class reader_rdata;
	class writer;

	template<qtype RType, qclass RClass>
	struct record_traits {
		using rdata_type = void;
	};

	template<>
	struct record_traits<qtype::a, qclass::in> {
		using rdata_type = ipv4_address;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	template<>
	struct record_traits<qtype::ns, qclass::in> {
		using rdata_type = qname;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	template<>
	struct record_traits<qtype::md, qclass::in> {
		using rdata_type = qname;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	template<>
	struct record_traits<qtype::mf, qclass::in> {
		using rdata_type = qname;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	template<>
	struct record_traits<qtype::cname, qclass::in> {
		using rdata_type = qname;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	struct soa_record {
		qname mname{};
        qname rname{};
        uint32_t serial{};
        std::chrono::seconds refresh{};
        std::chrono::seconds retry{};
        std::chrono::seconds expire{};
        std::chrono::seconds minimum{};
	};

	template<>
	struct record_traits<qtype::soa, qclass::in> {
		using rdata_type = soa_record;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	template<>
	struct record_traits<qtype::mb, qclass::in> {
		using rdata_type = qname;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	template<>
	struct record_traits<qtype::mg, qclass::in> {
		using rdata_type = qname;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	template<>
	struct record_traits<qtype::mr, qclass::in> {
		using rdata_type = qname;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	template<>
	struct record_traits<qtype::null, qclass::in> {
		using rdata_type = std::vector<std::byte>;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	struct wks_record {
		ipv4_address address;
		uint8_t protocol;
		std::array<uint8_t, 65536/8> ports;
	};

	template<>
	struct record_traits<qtype::wks, qclass::in> {
		using rdata_type = wks_record;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	template<>
	struct record_traits<qtype::ptr, qclass::in> {
		using rdata_type = qname;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	struct hinfo_record {
		std::string cpu;
		std::string os;
	};

	template<>
	struct record_traits<qtype::hinfo, qclass::in> {
		using rdata_type = hinfo_record;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	struct minfo_record {
		qname rmailbx;
		qname emailbx;
	};

	template<>
	struct record_traits<qtype::minfo, qclass::in> {
		using rdata_type = minfo_record;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	struct mx_record {
		uint16_t preference;
		qname exchange;
	};

	template<>
	struct record_traits<qtype::mx, qclass::in> {
		using rdata_type = mx_record;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	template<>
	struct record_traits<qtype::txt, qclass::in> {
		using rdata_type = std::vector<std::string>;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	struct rp_record {
		qname mbox;
		qname txt;
	};

	template<>
	struct record_traits<qtype::rp, qclass::in> {
		using rdata_type = rp_record;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	struct afsdb_record {
		uint16_t subtype;
		qname hostname;
	};

	template<>
	struct record_traits<qtype::afsdb, qclass::in> {
		using rdata_type = afsdb_record;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	template<>
	struct record_traits<qtype::x25, qclass::in> {
		using rdata_type = std::string;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	struct isdn_record {
		std::string address;
		std::string sa;
	};

	template<>
	struct record_traits<qtype::isdn, qclass::in> {
		using rdata_type = isdn_record;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	struct rt_record {
		uint16_t preference;
		qname intermediate_host;
	};

	template<>
	struct record_traits<qtype::rt, qclass::in> {
		using rdata_type = rt_record;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	template<>
	struct record_traits<qtype::nsap, qclass::in> {
		using rdata_type = std::vector<std::byte>;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	template<>
	struct record_traits<qtype::nsap_ptr, qclass::in> {
		using rdata_type = qname;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	template<>
	struct record_traits<qtype::aaaa, qclass::in> {
		using rdata_type = ipv6_address;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	struct srv_record {
		uint16_t priority;
		uint16_t weight;
		uint16_t port;
		qname target;
	};

	template<>
	struct record_traits<qtype::srv, qclass::in> {
		using rdata_type = srv_record;
		static void parse(rdata_type&, reader_rdata&);
		static void serialize(const rdata_type&, writer&);
	};

	/* Records still missing:
		sig = 24,
		key = 25,
		px = 26,
		gpos = 27,
		loc = 29,
		nxt = 30,
		eid = 31,
		nimloc = 32,
		atma = 34,
		naptr = 35,
		kx = 36,
		cert = 37,
		a6 = 38,
		dname = 39,
		sink = 40,
		opt = 41,
		apl = 42,
		ds = 43,
		sshfp = 44,
		ipseckey = 45,
		rrsig = 46,
		nsec = 47,
		dnskey = 48,
		dhcid = 49,
		nsec3 = 50,
		nsec3param = 51,
		tlsa = 52,
		smimea = 53,
		hip = 55,
		ninfo = 56,
		rkey = 57,
		talink = 58,
		cds = 59,
		cdnskey = 60,
		openpgpkey = 61,
		csync = 62,
		zonemd = 63,
		svcb = 64,
		https = 65,
		spf = 99,
		uinfo = 100,
		uid = 101,
		gid = 102,
		unspec = 103,
		nid = 104,
		l32 = 105,
		l64 = 106,
		lp = 107,
		eui48 = 108,
		eui64 = 109,
		tkey = 249,
		tsig = 250,
		ixfr = 251,
		axfr = 252,
		mailb = 253,
		maila = 254,
		any = 255,
		uri = 256,
		caa = 257,
		avc = 258,
		doa = 259,
		amtrelay = 260,
		resinfo = 261,
		wallet = 262,
		ta = 32768,
		dlv = 32769,
	*/

} // namespace asyncpp::io::dns