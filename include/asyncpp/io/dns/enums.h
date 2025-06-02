#pragma once
#include <cstdint>
#include <iosfwd>
#include <limits>

namespace asyncpp::io::dns {
	constexpr size_t max_message_size = std::numeric_limits<uint16_t>::max();
	constexpr size_t max_label_size = 63;
	constexpr size_t max_name_size = 255;
    constexpr size_t header_size = 12;

	enum class rcode : uint16_t {
		no_error = 0,		 // No error condition.
		form_error = 1,		 // The name server was unable to interpret the request due to a format error.
		server_failure = 2,	 // The name server encountered an internal failure while processing this request,
							 // for example an operating system error or a forwarding timeout.
		nx_domain = 3,		 // Some name that ought to exist, does not exist.
		not_implemented = 4, // The name server does not support the specified Opcode.
		refused = 5,	   // The name server refuses to perform the specified operation for policy or security reasons.
		domain_exists = 6, // Some name that ought not to exist, does exist.
		rrset_exists = 7,  // Some RRset that ought not to exist, does exist.
		nx_rrset = 8,	   // Some RRset that ought to exist, does not exist.
		not_authoritative = 9,	  // The server is not authoritative for the zone named in the Zone Section.
		not_zone = 10,			  // A name used in the Prerequisite or Update Section is
								  // not within the zone denoted by the Zone Section.
		dso_not_implemented = 11, // DSO Type not implemented
		bad_signature = 16,		  // tsig signature was invalid (likely invalid key).
		bad_key = 17,			  // TSIG Key is not known by server.
		bad_time = 18,			  // TSIG Timestamp was wrong (are your clocks in sync ?).
		bad_mode = 19,			  // TSIG mode unknown
		bad_name = 20,			  // Duplicate key name
		bad_alg = 21,			  // Algorithm not supported
		bad_trunc = 22,			  // Bad truncation
		bad_cookie = 23,		  // Bad/missing server cookie

        private_min = 3841,
        private_max = 4095,
	};

	enum class opcode : uint8_t {
		query = 0,
		iquery = 1,
		status = 2,
		notify = 4,
		update = 5,
		dso = 6,
	};

	enum class qtype : uint16_t {
		a = 1,
		ns = 2,
		md = 3,
		mf = 4,
		cname = 5,
		soa = 6,
		mb = 7,
		mg = 8,
		mr = 9,
		null = 10,
		wks = 11,
		ptr = 12,
		hinfo = 13,
		minfo = 14,
		mx = 15,
		txt = 16,
		rp = 17,
		afsdb = 18,
		x25 = 19,
		isdn = 20,
		rt = 21,
		nsap = 22,
		nsap_ptr = 23,
		sig = 24,
		key = 25,
		px = 26,
		gpos = 27,
		aaaa = 28,
		loc = 29,
		nxt = 30,
		eid = 31,
		nimloc = 32,
		srv = 33,
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
		private_min = 0xff00,
		private_max = 0xfffe,
	};

	enum class qclass : uint16_t {
		in = 1,
		csnet = 2,
		chaos = 3,
		hs = 4,
		none = 254,
		any = 255,
		private_min = 0xff00,
		private_max = 0xfffe,
	};

    enum class tsig_algorithm {
        hmac_md5,
        hmac_sha1,
        hmac_sha224,
        hmac_sha256,
        hmac_sha256_128,
        hmac_sha384,
        hmac_sha384_192,
        hmac_sha512,
        hmac_sha512_256,
    };

	std::ostream& operator<<(std::ostream& s, rcode r);
	std::ostream& operator<<(std::ostream& s, opcode o);
	std::ostream& operator<<(std::ostream& s, qtype t);
	std::ostream& operator<<(std::ostream& s, qclass c);
	std::ostream& operator<<(std::ostream& s, tsig_algorithm a);

} // namespace asyncpp::io::dns
