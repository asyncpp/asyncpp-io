#include <asyncpp/io/dns/enums.h>

#include <ostream>

namespace asyncpp::io::dns {

	std::ostream& operator<<(std::ostream& s, rcode r) {
		switch (r) {
		case rcode::no_error: return s << "no_error";
		case rcode::form_error: return s << "form_error";
		case rcode::server_failure: return s << "server_failure";
		case rcode::nx_domain: return s << "nx_domain";
		case rcode::not_implemented: return s << "not_implemented";
		case rcode::refused: return s << "refused";
		case rcode::domain_exists: return s << "domain_exists";
		case rcode::rrset_exists: return s << "rrset_exists";
		case rcode::nx_rrset: return s << "nx_rrset";
		case rcode::not_authoritative: return s << "not_authoritative";
		case rcode::not_zone: return s << "not_zone";
		case rcode::dso_not_implemented: return s << "dso_not_implemented";
		case rcode::bad_signature: return s << "bad_signature";
		case rcode::bad_key: return s << "bad_key";
		case rcode::bad_time: return s << "bad_time";
		case rcode::bad_mode: return s << "bad_mode";
		case rcode::bad_name: return s << "bad_name";
		case rcode::bad_alg: return s << "bad_alg";
		case rcode::bad_trunc: return s << "bad_trunc";
		case rcode::bad_cookie: return s << "bad_cookie";
        case rcode::private_min: break;
        case rcode::private_max: break;
		}
		if(r >= rcode::private_min && r <= rcode::private_max)
			return s << "private(" << (static_cast<uint16_t>(r) - static_cast<uint16_t>(rcode::private_min)) << ")";
		return s << static_cast<uint16_t>(r);
	}

	std::ostream& operator<<(std::ostream& s, opcode o) {
		switch (o) {
		case opcode::query: return s << "query";
		case opcode::iquery: return s << "iquery";
		case opcode::status: return s << "status";
		case opcode::notify: return s << "notify";
		case opcode::update: return s << "update";
		case opcode::dso: return s << "dso";
		}
		return s << static_cast<uint16_t>(o);
	}

	std::ostream& operator<<(std::ostream& s, qtype t) {
		switch (t) {
		case qtype::a: return s << "A";
		case qtype::ns: return s << "NS";
		case qtype::md: return s << "MD";
		case qtype::mf: return s << "MF";
		case qtype::cname: return s << "CNAME";
		case qtype::soa: return s << "SOA";
		case qtype::mb: return s << "MB";
		case qtype::mg: return s << "MG";
		case qtype::mr: return s << "MR";
		case qtype::null: return s << "NULL";
		case qtype::wks: return s << "WKS";
		case qtype::ptr: return s << "PTR";
		case qtype::hinfo: return s << "HINFO";
		case qtype::minfo: return s << "MINFO";
		case qtype::mx: return s << "MX";
		case qtype::txt: return s << "TXT";
		case qtype::rp: return s << "RP";
		case qtype::afsdb: return s << "AFSDB";
		case qtype::x25: return s << "X25";
		case qtype::isdn: return s << "ISDN";
		case qtype::rt: return s << "RT";
		case qtype::nsap: return s << "NSAP";
		case qtype::nsap_ptr: return s << "NSAP_PTR";
		case qtype::sig: return s << "SIG";
		case qtype::key: return s << "KEY";
		case qtype::px: return s << "PX";
		case qtype::gpos: return s << "GPOS";
		case qtype::aaaa: return s << "AAAA";
		case qtype::loc: return s << "LOC";
		case qtype::nxt: return s << "NXT";
		case qtype::eid: return s << "EID";
		case qtype::nimloc: return s << "NIMLOC";
		case qtype::srv: return s << "SRV";
		case qtype::atma: return s << "ATMA";
		case qtype::naptr: return s << "NAPTR";
		case qtype::kx: return s << "KX";
		case qtype::cert: return s << "CERT";
		case qtype::a6: return s << "A6";
		case qtype::dname: return s << "DNAME";
		case qtype::sink: return s << "SINK";
		case qtype::opt: return s << "OPT";
		case qtype::apl: return s << "APL";
		case qtype::ds: return s << "DS";
		case qtype::sshfp: return s << "SSHFP";
		case qtype::ipseckey: return s << "IPSECKEY";
		case qtype::rrsig: return s << "RRSIG";
		case qtype::nsec: return s << "NSEC";
		case qtype::dnskey: return s << "DNSKEY";
		case qtype::dhcid: return s << "DHCID";
		case qtype::nsec3: return s << "NSEC3";
		case qtype::nsec3param: return s << "NSEC3PARAM";
		case qtype::tlsa: return s << "TLSA";
		case qtype::smimea: return s << "SMIMEA";
		case qtype::hip: return s << "HIP";
		case qtype::ninfo: return s << "NINFO";
		case qtype::rkey: return s << "RKEY";
		case qtype::talink: return s << "TALINK";
		case qtype::cds: return s << "CDS";
		case qtype::cdnskey: return s << "CDNSKEY";
		case qtype::openpgpkey: return s << "OPENPGPKEY";
		case qtype::csync: return s << "CSYNC";
		case qtype::zonemd: return s << "ZONEMD";
		case qtype::svcb: return s << "SVCB";
		case qtype::https: return s << "HTTPS";
		case qtype::spf: return s << "SPF";
		case qtype::uinfo: return s << "UINFO";
		case qtype::uid: return s << "UID";
		case qtype::gid: return s << "GID";
		case qtype::unspec: return s << "UNSPEC";
		case qtype::nid: return s << "NID";
		case qtype::l32: return s << "L32";
		case qtype::l64: return s << "L64";
		case qtype::lp: return s << "LP";
		case qtype::eui48: return s << "EUI48";
		case qtype::eui64: return s << "EUI64";
		case qtype::tkey: return s << "TKEY";
		case qtype::tsig: return s << "TSIG";
		case qtype::ixfr: return s << "IXFR";
		case qtype::axfr: return s << "AXFR";
		case qtype::mailb: return s << "MAILB";
		case qtype::maila: return s << "MAILA";
		case qtype::any: return s << "ANY";
		case qtype::uri: return s << "URI";
		case qtype::caa: return s << "CAA";
		case qtype::avc: return s << "AVC";
		case qtype::doa: return s << "DOA";
		case qtype::amtrelay: return s << "AMTRELAY";
		case qtype::resinfo: return s << "RESINFO";
		case qtype::wallet: return s << "WALLET";
		case qtype::ta: return s << "TA";
		case qtype::dlv: return s << "DLV";
		case qtype::private_min:
		case qtype::private_max: break;
		}
		if(t >= qtype::private_min && t <= qtype::private_max)
			return s << "private(" << (static_cast<uint16_t>(t) - static_cast<uint16_t>(qtype::private_min)) << ")";
		return s << static_cast<uint16_t>(t);
	}

	std::ostream& operator<<(std::ostream& s, qclass c) {
		switch (c) {
		case qclass::in: return s << "IN";
		case qclass::csnet: return s << "CSNET";
		case qclass::chaos: return s << "CHAOS";
		case qclass::hs: return s << "HS";
		case qclass::none: return s << "NONE";
		case qclass::any: return s << "ANY";
		case qclass::private_min:
		case qclass::private_max: break;
		}
		if(c >= qclass::private_min && c <= qclass::private_max)
			return s << "private(" << (static_cast<uint16_t>(c) - static_cast<uint16_t>(qclass::private_min)) << ")";
		return s << static_cast<uint16_t>(c);
	}

	std::ostream& operator<<(std::ostream& s, tsig_algorithm a) {
		switch (a) {
		case tsig_algorithm::hmac_md5: return s << "hmac_md5";
		case tsig_algorithm::hmac_sha1: return s << "hmac_sha1";
		case tsig_algorithm::hmac_sha224: return s << "hmac_sha224";
		case tsig_algorithm::hmac_sha256: return s << "hmac_sha256";
		case tsig_algorithm::hmac_sha256_128: return s << "hmac_sha256_128";
		case tsig_algorithm::hmac_sha384: return s << "hmac_sha384";
		case tsig_algorithm::hmac_sha384_192: return s << "hmac_sha384_192";
		case tsig_algorithm::hmac_sha512: return s << "hmac_sha512";
		case tsig_algorithm::hmac_sha512_256: return s << "hmac_sha512_256";
		}
		return s << static_cast<uint16_t>(a);
	}
}