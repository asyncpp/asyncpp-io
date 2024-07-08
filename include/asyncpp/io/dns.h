#pragma once
#include <asyncpp/io/buffer.h>
#include <asyncpp/io/endpoint.h>
#include <asyncpp/io/io_service.h>
#include <asyncpp/io/socket.h>
#include <asyncpp/stop_token.h>
#include <asyncpp/timer.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iosfwd>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <vector>

namespace asyncpp::io::dns {
	enum class api_error : int {
		ok = 0,
		not_enough_space,
		label_invalid,
		label_too_long,
		incomplete_message,
		recursion_limit_exceeded,
		extra_data,
		duplicate_id,
		no_id,

		cancelled,
		timeout,
		internal,
	};
	const std::error_category& error_category() noexcept;
	inline std::error_code make_error_code(api_error e) noexcept {
		return std::error_code(static_cast<int>(e), error_category());
	}
} // namespace asyncpp::io::dns
namespace std {
	template<>
	struct is_error_code_enum<asyncpp::io::dns::api_error> : std::true_type {};
} // namespace std
namespace asyncpp::io::dns {
	constexpr size_t max_message_size = std::numeric_limits<uint16_t>::max();
	constexpr size_t max_label_size = 63;
	constexpr size_t max_name_size = 255;

	enum class rcode : uint8_t {
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
		not_authoritative = 9, // The server is not authoritative for the zone named in the Zone Section.
		not_zone = 10,		   // A name used in the Prerequisite or Update Section is
							   // not within the zone denoted by the Zone Section.
		bad_signature = 16,	   // tsig signature was invalid (likely invalid key).
		bad_key = 17,		   // TSIG Key is not known by server.
		bad_time = 18,		   // TSIG Timestamp was wrong (are your clocks in sync ?).
	};

	enum class opcode : uint8_t {
		query = 0,
		iquery = 1,
		status = 2,
		update = 5,
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
		ta = 32768,
		dlv = 32769,
	};

	enum class qclass : uint16_t {
		in = 1, /*%< Internet. */
		csnet = 2,
		chaos = 3, /*%< MIT Chaos-net. */
		hs = 4,	   /*%< MIT Hesiod. */
		any = 0xff,
	};

	class binary_writer {
		uint8_t* const m_start{};
		uint8_t* m_end{};
		uint8_t* const m_cap{};
		bool m_truncated{};
		bool m_throwing{};

		uint8_t* alloc(size_t n) {
			if (n > remaining_space() || m_truncated) {
				m_truncated = true;
				if (m_throwing) throw std::out_of_range("not enough remaining space");
				return nullptr;
			}
			auto ptr = m_end;
			m_end += n;
			return ptr;
		}

	public:
		binary_writer(uint8_t* ptr, size_t size) : m_start(ptr), m_end(ptr), m_cap(ptr + size) {}

		size_t remaining_space() const noexcept { return m_cap - m_end; }
		size_t used_space() const noexcept { return m_end - m_start; }
		size_t total_space() const noexcept { return m_cap - m_start; }
		bool is_truncated() const noexcept { return m_truncated; }
		binary_writer& set_throwing(bool throwing) noexcept {
			m_throwing = throwing;
			return *this;
		}

		binary_writer& u8(uint8_t val) {
			if (auto p = alloc(1); p) *p = val;
			return *this;
		}
		binary_writer& u16(uint16_t val, std::endian e = std::endian::little) {
			if (auto p = alloc(2); p) {
				p[0] = val & 0xff;
				p[1] = (val >> 8) & 0xff;
				if (e != std::endian::little) std::reverse(p, p + 2);
			}
			return *this;
		}
		binary_writer& u24(uint32_t val, std::endian e = std::endian::little) {
			if (auto p = alloc(3); p) {
				p[0] = val & 0xff;
				p[1] = (val >> 8) & 0xff;
				p[2] = (val >> 16) & 0xff;
				if (e != std::endian::little) std::reverse(p, p + 3);
			}
			return *this;
		}
		binary_writer& u32(uint32_t val, std::endian e = std::endian::little) {
			if (auto p = alloc(4); p) {
				p[0] = val & 0xff;
				p[1] = (val >> 8) & 0xff;
				p[2] = (val >> 16) & 0xff;
				p[3] = (val >> 24) & 0xff;
				if (e != std::endian::little) std::reverse(p, p + 4);
			}
			return *this;
		}
		binary_writer& u40(uint64_t val, std::endian e = std::endian::little) {
			if (auto p = alloc(5); p) {
				p[0] = val & 0xff;
				p[1] = (val >> 8) & 0xff;
				p[2] = (val >> 16) & 0xff;
				p[3] = (val >> 24) & 0xff;
				p[4] = (val >> 32) & 0xff;
				if (e != std::endian::little) std::reverse(p, p + 5);
			}
			return *this;
		}
		binary_writer& u48(uint64_t val, std::endian e = std::endian::little) {
			if (auto p = alloc(6); p) {
				p[0] = val & 0xff;
				p[1] = (val >> 8) & 0xff;
				p[2] = (val >> 16) & 0xff;
				p[3] = (val >> 24) & 0xff;
				p[4] = (val >> 32) & 0xff;
				p[5] = (val >> 40) & 0xff;
				if (e != std::endian::little) std::reverse(p, p + 6);
			}
			return *this;
		}
		binary_writer& u56(uint64_t val, std::endian e = std::endian::little) {
			if (auto p = alloc(7); p) {
				p[0] = val & 0xff;
				p[1] = (val >> 8) & 0xff;
				p[2] = (val >> 16) & 0xff;
				p[3] = (val >> 24) & 0xff;
				p[4] = (val >> 32) & 0xff;
				p[5] = (val >> 40) & 0xff;
				p[6] = (val >> 48) & 0xff;
				if (e != std::endian::little) std::reverse(p, p + 7);
			}
			return *this;
		}
		binary_writer& u64(uint64_t val, std::endian e = std::endian::little) {
			if (auto p = alloc(8); p) {
				p[0] = val & 0xff;
				p[1] = (val >> 8) & 0xff;
				p[2] = (val >> 16) & 0xff;
				p[3] = (val >> 24) & 0xff;
				p[4] = (val >> 32) & 0xff;
				p[5] = (val >> 40) & 0xff;
				p[6] = (val >> 48) & 0xff;
				p[7] = (val >> 56) & 0xff;
				if (e != std::endian::little) std::reverse(p, p + 8);
			}
			return *this;
		}
		binary_writer& raw(const void* ptr, size_t len, std::endian e = std::endian::native) {
			if (auto p = alloc(len); p) {
				memcpy(p, ptr, len);
				if (e != std::endian::little) std::reverse(p, p + len);
			}
			return *this;
		}
		binary_writer& dns_name(std::string_view name, std::map<std::string, size_t, std::less<>>* compress = nullptr) {
			if (compress != nullptr) {
				if (auto it = compress->find(name); it != compress->end()) {
					u16(0xc000 | it->second, std::endian::big);
					return *this;
				}
				compress->emplace(name, used_space());
			}

			std::string_view part = name.substr(0, name.find('.'));
			name.remove_prefix(part.size() + 1);
			while (!part.empty()) {
				u8(part.size());
				raw(part.data(), part.size());
				if (compress != nullptr) {
					if (auto it = compress->find(name); it != compress->end()) {
						u16(0xc000 | it->second, std::endian::big);
						return *this;
					}
					if (!name.empty()) compress->emplace(name, used_space());
				}
				part = name.substr(0, name.find('.'));
				name.remove_prefix(part.size() + 1);
			}
			u8(0);
			return *this;
		}
	};

	size_t convert_name(void* out, size_t outlen, std::string_view name, std::error_code& ec) noexcept;
	/**
	 * \brief Parses a label and resolves all pointers. Returns the end of the initial label.
	 * 
	 * \param msg The entire dns message for resolving pointers
	 * \param label Start of the label
	 * \param res Out param for the parsed string
	 * \return End of the first label/piece or nullptr if an error occurred
	 */
	const std::byte* parse_label(const_buffer msg, const std::byte* label, std::string& res,
								 std::error_code& ec) noexcept;

	struct mx_record {
		uint16_t preference;
		std::string name;
	};
	struct soa_record {
		std::string name;
		std::string rname;
		uint32_t serial;
		uint32_t refresh;
		uint32_t retry;
		uint32_t expire;
		uint32_t minimum;
	};
	struct srv_record {
		uint16_t priority;
		uint16_t weight;
		uint16_t port;
		std::string target;
	};
	struct tsig_record {
		std::string algorithm;
		std::chrono::system_clock::time_point timestamp;
		uint16_t fudge;
		std::vector<uint8_t> mac;
		uint16_t original_id;
		rcode error;
		std::vector<uint8_t> other;
	};

	ipv4_address parse_a(const_buffer data, const_buffer msg, std::error_code& ec) noexcept;
	ipv6_address parse_aaaa(const_buffer data, const_buffer msg, std::error_code& ec) noexcept;
	std::string parse_txt(const_buffer data, const_buffer msg, std::error_code& ec) noexcept;
	std::string parse_cname(const_buffer data, const_buffer msg, std::error_code& ec) noexcept;
	std::string parse_ns(const_buffer data, const_buffer msg, std::error_code& ec) noexcept;
	mx_record parse_mx(const_buffer data, const_buffer msg, std::error_code& ec);
	std::string parse_ptr(const_buffer data, const_buffer msg, std::error_code& ec) noexcept;
	soa_record parse_soa(const_buffer data, const_buffer msg, std::error_code& ec);
	srv_record parse_srv(const_buffer data, const_buffer msg, std::error_code& ec);
	tsig_record parse_tsig(const_buffer data, const_buffer msg, std::error_code& ec);

	std::vector<uint8_t> build_a(ipv4_address addr);
	std::vector<uint8_t> build_aaaa(ipv6_address addr);
	std::vector<uint8_t> build_txt(std::string_view str);
	std::vector<uint8_t> build_cname(std::string_view str);
	std::vector<uint8_t> build_ns(std::string_view str);
	std::vector<uint8_t> build_mx(const mx_record& rr);
	std::vector<uint8_t> build_ptr(std::string_view str);
	std::vector<uint8_t> build_soa(const soa_record& rr);
	std::vector<uint8_t> build_srv(const srv_record& rr);
	std::vector<uint8_t> build_tsig(const tsig_record& rr);

	class message_header {
		uint8_t m_data[12]{};

	public:
		message_header(const_buffer msg) { memcpy(m_data, msg.data(), (std::min<size_t>)(msg.size(), 12)); }

		uint16_t id() const noexcept { return raw_get<uint16_t, std::endian::big>(m_data); }
		constexpr bool qr() const noexcept { return (m_data[2] & 0x80) != 0; }
		constexpr dns::opcode opcode() const noexcept { return static_cast<dns::opcode>((m_data[2] >> 3) & 0x0f); }
		constexpr bool authoritative() const noexcept { return (m_data[2] & 0x04) != 0; }
		constexpr bool truncated() const noexcept { return (m_data[2] & 0x02) != 0; }
		constexpr bool recursion_desired() const noexcept { return (m_data[2] & 0x01) != 0; }
		constexpr bool recursion_available() const noexcept { return (m_data[3] & 0x80) != 0; }
		constexpr dns::rcode rcode() const noexcept { return static_cast<dns::rcode>(m_data[3] & 0x0f); }

		uint16_t query_count() const noexcept { return raw_get<uint16_t, std::endian::big>(m_data + 4); }
		uint16_t answer_count() const noexcept { return raw_get<uint16_t, std::endian::big>(m_data + 6); }
		uint16_t authoritative_count() const noexcept { return raw_get<uint16_t, std::endian::big>(m_data + 8); }
		uint16_t additional_count() const noexcept { return raw_get<uint16_t, std::endian::big>(m_data + 10); }
	};

	template<typename T>
	concept MessageVisitor = //
		requires(T& v) {
			{
				v.on_header(std::declval<const message_header&>(), std::declval<const const_buffer&>())
			} -> std::convertible_to<bool>;
			{
				v.on_question(std::declval<std::string_view>(), std::declval<qtype>(), std::declval<qclass>())
			} -> std::convertible_to<bool>;
			{
				v.on_answer(std::declval<std::string_view>(), std::declval<qtype>(), std::declval<qclass>(),
							std::declval<uint32_t>(), std::declval<const_buffer>())
			} -> std::convertible_to<bool>;
			{
				v.on_authority(std::declval<std::string_view>(), std::declval<qtype>(), std::declval<qclass>(),
							   std::declval<uint32_t>(), std::declval<const_buffer>())
			} -> std::convertible_to<bool>;
			{
				v.on_additional(std::declval<std::string_view>(), std::declval<qtype>(), std::declval<qclass>(),
								std::declval<uint32_t>(), std::declval<const_buffer>())
			} -> std::convertible_to<bool>;
		};

	inline bool visit_message(const_buffer msg, MessageVisitor auto& visitor, std::error_code& ec) {
		const auto pmsg = msg.data();
		const auto pend = pmsg + msg.size();
		if (msg.size() < 12) {
			ec = api_error::incomplete_message;
			return false;
		}
		message_header hdr(msg);
		if (!visitor.on_header(hdr, msg)) return false;
		const std::byte* ptr = pmsg + 12;
		std::string name;
		for (size_t i = hdr.query_count(); i > 0; i--) {
			name.clear();
			const auto pfixed = parse_label(msg, ptr, name, ec);
			if (ec) return false;
			if (pfixed == nullptr || (pfixed + 4) > (pend)) {
				ec = api_error::incomplete_message;
				return false;
			}
			auto qtype = raw_get<dns::qtype, std::endian::big>(pfixed);
			auto qclass = raw_get<dns::qclass, std::endian::big>(pfixed + 2);
			if (!visitor.on_question(name, qtype, qclass)) return false;
			ptr = pfixed + 4;
		}
		const auto answers = hdr.answer_count();
		const auto authorities = hdr.authoritative_count();
		const auto additionals = hdr.additional_count();
		for (size_t i = answers + authorities + additionals; i > 0; i--) {
			name.clear();
			const auto pfixed = parse_label(msg, ptr, name, ec);
			if (ec) return false;
			if (pfixed == nullptr || (pfixed + 10) > (pend)) {
				ec = api_error::incomplete_message;
				return false;
			}
			const auto rtype = raw_get<qtype, std::endian::big>(pfixed);
			const auto rclass = raw_get<qclass, std::endian::big>(pfixed + 2);
			const auto ttl = raw_get<uint32_t, std::endian::big>(pfixed + 4);
			const auto rdata_len = raw_get<uint16_t, std::endian::big>(pfixed + 8);
			if (pfixed + 10 + rdata_len > pend) {
				ec = api_error::incomplete_message;
				return false;
			}
			if (i > authorities + additionals) {
				if (!visitor.on_answer(name, rtype, rclass, ttl, const_buffer(pfixed + 10, rdata_len))) return false;
			} else if (i > additionals) {
				if (!visitor.on_authority(name, rtype, rclass, ttl, const_buffer(pfixed + 10, rdata_len))) return false;
			} else {
				if (!visitor.on_additional(name, rtype, rclass, ttl, const_buffer(pfixed + 10, rdata_len)))
					return false;
			}
			ptr = pfixed + 10 + rdata_len;
		}
		if (ptr != pend) {
			ec = api_error::extra_data;
			return false;
		}
		return true;
	}

	inline bool visit_message(const_buffer msg, MessageVisitor auto& visitor) {
		std::error_code ec;
		auto res = visit_message(msg, visitor, ec);
		if (res && ec) throw std::system_error(ec);
		return res;
	}

	struct question {
		std::string name;
		dns::qtype qtype;
		dns::qclass qclass;

		std::vector<uint8_t> serialize() const;
		const std::byte* parse(const_buffer msg, const std::byte* const rr);
	};

	struct resource_record {
		std::string name;
		qtype rtype;
		qclass rclass;
		uint32_t ttl;
		std::vector<uint8_t> rdata;

		std::vector<uint8_t> serialize() const;
		const std::byte* parse(const_buffer msg, const std::byte* const rr);
	};

	class message_builder {
		uint8_t* const m_start;
		uint8_t* m_end;
		uint8_t* const m_cap;
		uint8_t* m_question_end;
		uint8_t* m_answer_end;
		uint8_t* m_authority_end;
		bool m_truncated{};

		template<size_t pos, uint8_t mask, uint8_t shift>
		uint8_t get_flag() {
			return (m_start[pos] & mask) >> shift;
		}

		template<size_t pos, uint8_t mask, uint8_t shift>
		void set_flag(uint8_t value) {
			auto v = m_start[pos] & ~mask;
			v |= ((value << shift) & mask);
			m_start[pos] = v;
		}

	public:
		message_builder(void* buf, size_t buf_size) noexcept
			: m_start(static_cast<uint8_t*>(buf)), m_end(m_start + 12), m_cap(m_start + buf_size) {
			m_question_end = m_answer_end = m_authority_end = m_end;
			if (m_cap < m_end) m_truncated = true;
			memset(m_start, 0, (std::min<size_t>)(m_cap - m_start, 12));
		}

		message_builder& set_id(uint16_t id) noexcept {
			raw_set<uint16_t, std::endian::big>(m_start, id);
			return *this;
		}
		message_builder& set_qr(bool is_response) noexcept {
			set_flag<2, 0x80, 7>(is_response);
			return *this;
		}
		message_builder& set_opcode(opcode op) noexcept {
			set_flag<2, 0x78, 3>(static_cast<uint8_t>(op));
			return *this;
		}
		message_builder& set_authoritative(bool aa) noexcept {
			set_flag<2, 0x04, 2>(aa);
			return *this;
		}
		message_builder& set_truncated(bool tc) noexcept {
			set_flag<2, 0x02, 1>(tc);
			return *this;
		}
		message_builder& set_recursion_desired(bool rd) noexcept {
			set_flag<2, 0x01, 0>(rd);
			return *this;
		}
		message_builder& set_recursion_available(bool ra) noexcept {
			set_flag<3, 0x80, 7>(ra);
			return *this;
		}
		message_builder& set_rcode(rcode code) noexcept {
			set_flag<3, 0x0f, 0>(static_cast<uint8_t>(code));
			return *this;
		}
		template<typename T>
		message_builder& add_question(const T& record) noexcept {
			if (m_truncated) return *this;
			if (m_cap - m_end < record.size()) {
				m_truncated = true;
				set_truncated(true);
				return *this;
			}
			memmove(m_question_end + record.size(), m_question_end, m_end - m_question_end);
			memcpy(m_question_end, record.data(), record.size());
			raw_set<uint16_t, std::endian::big>(m_start + 4, raw_get<uint16_t, std::endian::big>(m_start + 4) + 1);
			m_question_end += record.size();
			m_answer_end += record.size();
			m_authority_end += record.size();
			m_end += record.size();
			return *this;
		}
		message_builder& add_question(std::string_view label, qtype qt, qclass qc) {
			auto record_size = label.size() + (label.empty() ? 1 : 2) + 4;
			if (m_truncated) return *this;
			if (m_cap - m_end < record_size) {
				m_truncated = true;
				set_truncated(true);
				return *this;
			}
			memmove(m_question_end + record_size, m_question_end, m_end - m_question_end);

			std::error_code ec;
			convert_name(m_question_end, record_size - 4, label, ec);
			if (ec) throw std::system_error(ec);
			raw_set<qtype, std::endian::big>(m_question_end + record_size - 4, qt);
			raw_set<qclass, std::endian::big>(m_question_end + record_size - 2, qc);

			raw_set<uint16_t, std::endian::big>(m_start + 4, raw_get<uint16_t, std::endian::big>(m_start + 4) + 1);
			m_question_end += record_size;
			m_answer_end += record_size;
			m_authority_end += record_size;
			m_end += record_size;
			return *this;
		}
		message_builder& add_question(const question& q) { return add_question(q.serialize()); }
		template<typename T>
		message_builder& add_answer(const T& record) {
			if (m_truncated) return *this;
			if (m_cap - m_end < record.size()) {
				m_truncated = true;
				set_truncated(true);
				return *this;
			}
			memmove(m_answer_end + record.size(), m_answer_end, m_end - m_answer_end);
			memcpy(m_answer_end, record.data(), record.size());
			raw_set<uint16_t, std::endian::big>(m_start + 6, raw_get<uint16_t, std::endian::big>(m_start + 6) + 1);
			m_answer_end += record.size();
			m_authority_end += record.size();
			m_end += record.size();
			return *this;
		}
		message_builder& add_answer(const resource_record& rr) { return add_answer(rr.serialize()); }
		message_builder& add_answer(std::string name, qtype rtype, qclass rclass, uint32_t ttl,
									std::vector<uint8_t> rdata) {
			resource_record rr;
			rr.name = std::move(name);
			rr.rtype = rtype;
			rr.rclass = rclass;
			rr.ttl = ttl;
			rr.rdata = std::move(rdata);
			return add_answer(std::move(rr));
		}
		template<typename T>
		message_builder& add_authority(const T& record) {
			if (m_truncated) return *this;
			if (m_cap - m_end < record.size()) {
				m_truncated = true;
				set_truncated(true);
				return *this;
			}
			memmove(m_authority_end + record.size(), m_authority_end, m_end - m_authority_end);
			memcpy(m_authority_end, record.data(), record.size());
			raw_set<uint16_t, std::endian::big>(m_start + 8, raw_get<uint16_t, std::endian::big>(m_start + 8) + 1);
			m_authority_end += record.size();
			m_end += record.size();
			return *this;
		}
		message_builder& add_authority(const resource_record& rr) { return add_authority(rr.serialize()); }
		message_builder& add_authority(std::string name, qtype rtype, qclass rclass, uint32_t ttl,
									   std::vector<uint8_t> rdata) {
			resource_record rr;
			rr.name = std::move(name);
			rr.rtype = rtype;
			rr.rclass = rclass;
			rr.ttl = ttl;
			rr.rdata = std::move(rdata);
			return add_authority(std::move(rr));
		}

		template<typename T>
		message_builder& add_additional(const T& record) {
			if (m_truncated) return *this;
			if (m_cap - m_end < record.size()) {
				m_truncated = true;
				set_truncated(true);
				return *this;
			}
			memcpy(m_end, record.data(), record.size());
			raw_set<uint16_t, std::endian::big>(m_start + 10, raw_get<uint16_t, std::endian::big>(m_start + 10) + 1);
			m_end += record.size();
			return *this;
		}
		message_builder& add_additional(const resource_record& rr) { return add_additional(rr.serialize()); }
		message_builder& add_additional(std::string name, qtype rtype, qclass rclass, uint32_t ttl,
										std::vector<uint8_t> rdata) {
			resource_record rr;
			rr.name = std::move(name);
			rr.rtype = rtype;
			rr.rclass = rclass;
			rr.ttl = ttl;
			rr.rdata = std::move(rdata);
			return add_additional(std::move(rr));
		}

		size_t bytes_used() const noexcept { return m_end - m_start; }

		/** Aliases for RFC2136 */
		template<typename T>
		message_builder& add_zone(const T& record) noexcept {
			return add_question(record);
		}
		message_builder& add_zone(std::string_view label, qtype qt, qclass qc) { return add_question(label, qt, qc); }
		template<typename T>
		message_builder& add_prerequisite(const T& record) {
			return add_answer(record);
		}
		message_builder& add_prerequisite(std::string name, qtype rtype, qclass rclass, uint32_t ttl,
										  std::vector<uint8_t> rdata) {
			return add_answer(std::move(name), rtype, rclass, ttl, std::move(rdata));
		}
		template<typename T>
		message_builder& add_update(const T& record) {
			return add_authority(record);
		}
		message_builder& add_update(std::string name, qtype rtype, qclass rclass, uint32_t ttl,
									std::vector<uint8_t> rdata) {
			return add_authority(std::move(name), rtype, rclass, ttl, std::move(rdata));
		}

		message_builder& add_tsig_signature(std::string_view keyname, std::span<uint8_t> key);
	};

	struct message {
		uint16_t id;
		bool is_response;
		bool is_authoritative;
		bool is_truncated;
		bool is_recursion_desired;
		bool is_recursion_available;
		dns::opcode opcode;
		dns::rcode rcode;

		std::vector<question> questions;
		std::vector<resource_record> answers;
		std::vector<resource_record> authorities;
		std::vector<resource_record> additional;

		std::vector<uint8_t> serialize() const;
		void serialize(void* buf, size_t bufsize) const;
		void parse(const_buffer msg);
	};

	std::ostream& operator<<(std::ostream& s, rcode r);
	std::ostream& operator<<(std::ostream& s, opcode o);
	std::ostream& operator<<(std::ostream& s, qtype t);
	std::ostream& operator<<(std::ostream& s, qclass c);

	class print_message_visitor {
		std::ostream* m_out;
		const_buffer m_message;
		bool m_question_header_done{};
		bool m_answer_header_done{};
		bool m_authority_header_done{};
		bool m_additional_header_done{};
		bool m_is_update{};

		void print_rr(std::string_view name, qtype rtype, qclass rclass, uint32_t ttl, const_buffer rdata) noexcept;

	public:
		print_message_visitor(std::ostream& str) : m_out(&str) {}
		bool on_header(const message_header& hdr, const_buffer message) noexcept;
		bool on_question(std::string_view name, qtype qtype, qclass qclass) noexcept;
		bool on_answer(std::string_view name, qtype rtype, qclass rclass, uint32_t ttl, const_buffer rdata) noexcept;
		bool on_authority(std::string_view name, qtype rtype, qclass rclass, uint32_t ttl, const_buffer rdata) noexcept;
		bool on_additional(std::string_view name, qtype rtype, qclass rclass, uint32_t ttl,
						   const_buffer rdata) noexcept;
	};

	template<typename FN>
	void visit_answer(const_buffer msg, FN&& fn) {
		struct visitor {
			FN m_fn;
			bool on_header(const message_header& hdr, const_buffer message) noexcept {
				return hdr.answer_count() != 0 && hdr.rcode() == rcode::no_error;
			}
			bool on_question(std::string_view name, qtype qtype, qclass qclass) noexcept { return true; }
			bool on_answer(std::string_view name, qtype rtype, qclass rclass, uint32_t ttl,
						   const_buffer rdata) noexcept {
				return m_fn(name, rtype, rclass, ttl, rdata);
			}
			bool on_authority(std::string_view name, qtype rtype, qclass rclass, uint32_t ttl,
							  const_buffer rdata) noexcept {
				return false;
			}
			bool on_additional(std::string_view name, qtype rtype, qclass rclass, uint32_t ttl,
							   const_buffer rdata) noexcept {
				return false;
			}
		} visit{std::move(fn)};
		visit_message(msg, visit);
	}

	class client {
		class query_awaiter;

	public:
		client(io_service& service);
		client(const client&) = delete;
		client& operator=(const client&) = delete;
		client(client&&) = delete;
		client& operator=(client&&) = delete;
		~client();

		enum class protocol { udp };

		void add_nameserver(endpoint ep, protocol proto = protocol::udp) {
			std::unique_lock lck{m_mutex};
			m_nameservers.push_back(ep);
		}
		void add_nameserver(address addr, protocol proto = protocol::udp) { add_nameserver(endpoint(addr, 53), proto); }
		void set_timeout(std::chrono::milliseconds timeout);
		void set_retries(size_t retries) {
			std::unique_lock lck{m_mutex};
			m_retries = retries;
		}

		std::optional<uint16_t> get_free_id() const noexcept;

		void query(const_buffer query, std::function<void(api_error, const_buffer)> callback);
		query_awaiter query(const_buffer query) noexcept;

		void query(std::string_view name, dns::qtype qtype, dns::qclass qclass,
				   std::function<void(api_error, const_buffer)> callback);
		auto query(std::string_view name, dns::qtype qtype, dns::qclass qclass) noexcept;

		void resolve(std::string name, dns::qtype type, std::function<void(std::vector<address> res)> callback);
		auto resolve(std::string name, dns::qtype type) noexcept;

		void stop();

	private:
		struct request;
		mutable std::recursive_mutex m_mutex;
		asyncpp::stop_source m_stop;
		asyncpp::stop_source m_stop_timer;
		socket m_socket_ipv4;
		socket m_socket_ipv6;
		std::vector<endpoint> m_nameservers;
		std::map<uint16_t, request> m_inflight;
		std::chrono::milliseconds m_timeout{250};
		size_t m_retries{5};

		void send_requests(request& req);
	};

	class client::query_awaiter {
	protected:
		client* m_parent;
		asyncpp::coroutine_handle<> m_handle{};
		const_buffer m_query{};
		api_error m_result{};
		std::vector<std::byte> m_response{};

	public:
		query_awaiter(client* that, const_buffer query) noexcept : m_parent(that), m_query{query} {}

		constexpr bool await_ready() const noexcept { return false; }
		void await_suspend(asyncpp::coroutine_handle<> h) {
			m_parent->query(m_query, [h, this](api_error error, const_buffer response) {
				m_result = error;
				try {
					m_response.resize(response.size());
					memcpy(m_response.data(), response.data(), response.size());
				} catch (...) { m_result = api_error::not_enough_space; }
				h.resume();
			});
		}
		std::vector<std::byte> await_resume() {
			if (m_result != api_error::ok) throw make_error_code(m_result);
			return std::move(m_response);
		}
	};

	inline client::query_awaiter client::query(const_buffer query) noexcept { return query_awaiter(this, query); }
	inline auto client::query(std::string_view name, dns::qtype qtype, dns::qclass qclass) noexcept {
		class awaiter : public client::query_awaiter {
			std::vector<std::byte> m_buffer;

		public:
			awaiter(client* that, std::string_view name, dns::qtype qtype, dns::qclass qclass)
				: client::query_awaiter(that, {}) {
				m_buffer.resize(max_message_size);
				m_buffer.resize(message_builder(m_buffer.data(), m_buffer.size())
									.set_opcode(opcode::query)
									.set_recursion_desired(true)
									.add_question(name, qtype, qclass)
									.bytes_used());
				m_query = {m_buffer.data(), m_buffer.size()};
			}
		};
		return awaiter(this, name, qtype, qclass);
	}

	inline auto client::resolve(std::string name, qtype type) noexcept {
		struct awaiter {
			client* m_parent;
			std::string m_name;
			qtype m_type;
			asyncpp::coroutine_handle<> m_handle{};
			std::vector<address> m_response{};

			constexpr bool await_ready() const noexcept { return false; }
			void await_suspend(asyncpp::coroutine_handle<> h) {
				m_parent->resolve(std::move(m_name), m_type, [h, this](std::vector<address> res) {
					m_response = std::move(res);
					h.resume();
				});
			}
			std::vector<address> await_resume() { return std::move(m_response); }
		};
		return awaiter{this, std::move(name), type};
	}

} // namespace asyncpp::io::dns
