#include <asyncpp/io/dns.h>
#include <asyncpp/launch.h>
#include <asyncpp/scope_guard.h>
#include <asyncpp/task.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <mutex>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <system_error>

#include <openssl/evp.h>

#define FAIL_WITH(x, y)                                                                                                \
	{                                                                                                                  \
		ec = make_error_code(x);                                                                                       \
		return y;                                                                                                      \
	}
#define FAIL(x)                                                                                                        \
	{                                                                                                                  \
		ec = make_error_code(x);                                                                                       \
		return;                                                                                                        \
	}

namespace {
	template<typename TKey, typename... T>
	std::array<uint8_t, 16> calculate_md5(const TKey& key, const T&... vals) {
		auto mdctx = EVP_MD_CTX_new();
		asyncpp::scope_guard cleanup{[mdctx]() noexcept { EVP_MD_CTX_free(mdctx); }};
		if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) != 1) throw std::runtime_error("failed to init mac");
		if (((EVP_DigestUpdate(mdctx, vals.data(), vals.size()) != 1) || ...))
			throw std::runtime_error("failed to update mac");
		std::array<uint8_t, 16> md{};
		if (EVP_DigestFinal_ex(mdctx, md.data(), NULL) != 1) throw std::runtime_error("failed to finish mac");
		return md;
	}
} // namespace

namespace asyncpp::io::dns {

	const std::error_category& error_category() noexcept {
		class dns_category final : public std::error_category {
			const char* name() const noexcept override { return "dns"; }
			std::string message(int code) const override {
				switch (static_cast<api_error>(code)) {
				case api_error::ok: return "ok";
				case api_error::not_enough_space: return "not enough space";
				case api_error::label_invalid: return "label invalid";
				case api_error::label_too_long: return "label too long";
				case api_error::incomplete_message: return "incomplete or invalid message";
				case api_error::recursion_limit_exceeded: return "recursion limit exceeded";
				case api_error::extra_data: return "extra data in message";
				case api_error::duplicate_id: return "duplicate_id";
				case api_error::no_id: return "no_id";
				case api_error::cancelled: return "cancelled";
				case api_error::timeout: return "timeout";
				case api_error::internal: return "internal";
				default: return "<unknown>";
				}
			}
		};
		static const dns_category instance;
		return instance;
	}

	size_t convert_name(void* out, size_t outlen, std::string_view name, std::error_code& ec) noexcept {
		const size_t required_space = (name.empty() ? 1 : 2) + name.size();
		if (outlen < required_space) FAIL_WITH(api_error::not_enough_space, required_space);
		auto size = static_cast<char*>(out);
		*size = 0;
		auto ptr = size + 1;
		for (auto e : name) {
			if (ptr >= static_cast<char*>(out) + outlen) FAIL_WITH(api_error::not_enough_space, required_space);
			if (e == '.') {
				if (*size == 0) FAIL_WITH(api_error::label_invalid, required_space);
				size = ptr;
				*size = 0;
			} else {
				(*size)++;
				if (*size > max_label_size) { FAIL_WITH(api_error::label_too_long, required_space); }
				*ptr = e;
			}
			ptr++;
		}
		*ptr = 0;
		return required_space;
	}

	const std::byte* parse_label(std::span<const std::byte> msg, const std::byte* plabel, std::string& res,
								 std::error_code& ec) noexcept {
		auto pmsg = msg.data();

		const std::byte* first_label_end = nullptr;

		size_t depth = 0;

		while (plabel < pmsg + msg.size()) {
			if (static_cast<uint8_t>(*plabel) == 0) {
				return first_label_end ? first_label_end : (plabel + 1);
			} else if (static_cast<uint8_t>(*plabel) & 0xc0) {
				if (plabel + 1 >= pmsg + msg.size()) FAIL_WITH(api_error::incomplete_message, nullptr);
				auto offset = raw_get<uint16_t, std::endian::big>(plabel) & 0x3fff;
				if (pmsg + offset >= plabel) FAIL_WITH(api_error::incomplete_message, nullptr);
				first_label_end = plabel + 2;
				plabel = pmsg + offset;
				if (depth++ == 128) FAIL_WITH(api_error::recursion_limit_exceeded, nullptr);
			} else {
				if (plabel + static_cast<uint8_t>(*plabel) >= pmsg + msg.size())
					FAIL_WITH(api_error::incomplete_message, nullptr);
				if (!res.empty()) res += '.';
				res.resize(res.size() + static_cast<uint8_t>(*plabel));
				memcpy(res.data() + res.size() - static_cast<uint8_t>(*plabel), plabel + 1,
					   static_cast<uint8_t>(*plabel));
				plabel += static_cast<uint8_t>(*plabel) + 1;
			}
		}
		FAIL_WITH(api_error::incomplete_message, nullptr);
	}

	ipv4_address parse_a(const_buffer data, const_buffer msg, std::error_code& ec) noexcept {
		if (data.size() < 4) {
			ec = make_error_code(api_error::incomplete_message);
			return ipv4_address();
		} else {
			return ipv4_address(static_cast<uint8_t>(data[0]), static_cast<uint8_t>(data[1]),
								static_cast<uint8_t>(data[2]), static_cast<uint8_t>(data[3]));
		}
	}

	ipv6_address parse_aaaa(const_buffer data, const_buffer msg, std::error_code& ec) noexcept {
		if (data.size() < 16) {
			ec = make_error_code(api_error::incomplete_message);
			return ipv6_address();
		} else {
			return ipv6_address(
				std::span<const uint8_t, 16>(reinterpret_cast<const uint8_t*>(data.data()), data.size()));
		}
	}

	std::string parse_txt(const_buffer data, const_buffer msg, std::error_code& ec) noexcept {
		auto ptr = data.data();
		auto end = data.data() + data.size();
		std::string res;
		while (ptr < end) {
			auto len = static_cast<uint8_t>(*ptr);
			if (ptr + 1 + len > end) {
				res.append(reinterpret_cast<const char*>(ptr + 1), std::distance(ptr + 1, end));
				ec = make_error_code(api_error::incomplete_message);
				return res;
			} else {
				res.append(reinterpret_cast<const char*>(ptr + 1), len);
			}
			ptr += 1 + len;
		}
		return res;
	}

	std::string parse_cname(const_buffer data, const_buffer msg, std::error_code& ec) noexcept {
		std::string res;
		parse_label(msg, data.data(), res, ec);
		return res;
	}

	std::string parse_ns(const_buffer data, const_buffer msg, std::error_code& ec) noexcept {
		std::string res;
		parse_label(msg, data.data(), res, ec);
		return res;
	}

	mx_record parse_mx(const_buffer data, const_buffer msg, std::error_code& ec) {
		mx_record res;
		if (data.size() < 3) {
			ec = make_error_code(api_error::incomplete_message);
			return res;
		}
		res.preference = raw_get<uint16_t, std::endian::big>(data.data());
		parse_label(msg, data.data() + 2, res.name, ec);
		return res;
	}

	std::string parse_ptr(const_buffer data, const_buffer msg, std::error_code& ec) noexcept {
		std::string res;
		parse_label(msg, data.data(), res, ec);
		return res;
	}

	soa_record parse_soa(const_buffer data, const_buffer msg, std::error_code& ec) {
		soa_record res;
		if (data.size() < 20) {
			ec = make_error_code(api_error::incomplete_message);
			return res;
		}
		auto ptr = parse_label(msg, data.data(), res.name, ec);
		if (ec) return res;
		ptr = parse_label(msg, ptr, res.rname, ec);
		if (ec) return res;
		if (std::distance(ptr, data.data() + data.size()) < 20) {
			ec = make_error_code(api_error::incomplete_message);
			return res;
		}
		res.serial = raw_get<uint32_t, std::endian::big>(ptr);
		res.refresh = raw_get<uint32_t, std::endian::big>(ptr + 4);
		res.retry = raw_get<uint32_t, std::endian::big>(ptr + 8);
		res.expire = raw_get<uint32_t, std::endian::big>(ptr + 12);
		res.minimum = raw_get<uint32_t, std::endian::big>(ptr + 16);
		return res;
	}

	srv_record parse_srv(const_buffer data, const_buffer msg, std::error_code& ec) {
		srv_record res;
		if (data.size() < 7) {
			ec = make_error_code(api_error::incomplete_message);
			return res;
		}
		res.priority = raw_get<uint16_t, std::endian::big>(data.data());
		res.weight = raw_get<uint16_t, std::endian::big>(data.data() + 2);
		res.port = raw_get<uint16_t, std::endian::big>(data.data() + 4);
		auto ptr = parse_label(msg, data.data() + 6, res.target, ec);
		if (ptr != data.data() + data.size()) ec = make_error_code(api_error::extra_data);

		return res;
	}

	tsig_record parse_tsig(const_buffer data, const_buffer msg, std::error_code& ec) {
		tsig_record res;
		if (data.size() < 17) {
			ec = make_error_code(api_error::incomplete_message);
			return res;
		}
		auto ptr = parse_label(msg, data.data(), res.algorithm, ec);
		if (std::distance(ptr, data.data() + data.size()) < 16) {
			ec = make_error_code(api_error::incomplete_message);
			return res;
		}
		uint64_t ts{};
		ts |= static_cast<uint64_t>(*ptr++) << 40;
		ts |= static_cast<uint64_t>(*ptr++) << 32;
		ts |= static_cast<uint64_t>(*ptr++) << 24;
		ts |= static_cast<uint64_t>(*ptr++) << 16;
		ts |= static_cast<uint64_t>(*ptr++) << 8;
		ts |= static_cast<uint64_t>(*ptr++);
		res.timestamp = std::chrono::system_clock::from_time_t(ts);
		res.fudge = raw_get<uint16_t, std::endian::big>(ptr);
		res.mac.resize(raw_get<uint16_t, std::endian::big>(ptr + 2));
		ptr += 4;
		if (std::distance(ptr, data.data() + data.size()) < 6 + res.mac.size()) {
			ec = make_error_code(api_error::incomplete_message);
			return res;
		}
		memcpy(res.mac.data(), ptr, res.mac.size());
		ptr += res.mac.size();
		res.original_id = raw_get<uint16_t, std::endian::big>(ptr);
		res.error = static_cast<rcode>(raw_get<uint16_t, std::endian::big>(ptr + 2));
		res.other.resize(raw_get<uint16_t, std::endian::big>(ptr + 4));
		if (std::distance(ptr + 6, data.data() + data.size()) < res.other.size()) {
			ec = make_error_code(api_error::incomplete_message);
			return res;
		}
		memcpy(res.other.data(), ptr + 6, res.other.size());

		return res;
	}

	std::vector<uint8_t> build_a(ipv4_address addr) {
		const auto data = addr.data();
		return {data.begin(), data.end()};
	}

	std::vector<uint8_t> build_aaaa(ipv6_address addr) {
		const auto data = addr.data();
		return {data.begin(), data.end()};
	}

	std::vector<uint8_t> build_txt(std::string_view str) {
		std::vector<uint8_t> res;
		while (!str.empty()) {
			auto part = str.substr(0, 255);
			res.push_back(part.size());
			res.insert(res.end(), part.begin(), part.end());
			str.remove_prefix(part.size());
		}
		return res;
	}

	std::vector<uint8_t> build_cname(std::string_view str) {
		std::vector<uint8_t> res(256);
		std::error_code ec;
		auto len = convert_name(res.data(), res.size(), str, ec);
		if (ec) throw std::system_error(ec);
		res.resize(len);
		return res;
	}

	std::vector<uint8_t> build_ns(std::string_view str) {
		std::vector<uint8_t> res(256);
		std::error_code ec;
		auto len = convert_name(res.data(), res.size(), str, ec);
		if (ec) throw std::system_error(ec);
		res.resize(len);
		return res;
	}

	std::vector<uint8_t> build_mx(const mx_record& rr) {
		std::vector<uint8_t> res(2 + 256);
		if (rr.name.size() > 255) throw std::system_error(api_error::label_too_long);
		raw_set<uint16_t, std::endian::big>(res.data(), rr.preference);
		std::error_code ec;
		auto len = convert_name(res.data() + 2, res.size(), rr.name, ec);
		if (ec) throw std::system_error(ec);
		res.resize(2 + len);
		return res;
	}

	std::vector<uint8_t> build_ptr(std::string_view str) {
		std::vector<uint8_t> res(256);
		std::error_code ec;
		auto len = convert_name(res.data(), res.size(), str, ec);
		if (ec) throw std::system_error(ec);
		res.resize(len);
		return res;
	}

	std::vector<uint8_t> build_soa(const soa_record& rr) {
		std::vector<uint8_t> res(256 + 256 + 20);
		if (rr.name.size() > 255) throw std::system_error(api_error::label_too_long);
		if (rr.rname.size() > 255) throw std::system_error(api_error::label_too_long);
		std::error_code ec;
		auto len = convert_name(res.data(), res.size(), rr.name, ec);
		if (ec) throw std::system_error(ec);
		len += convert_name(res.data() + len, res.size() - len, rr.rname, ec);
		if (ec) throw std::system_error(ec);
		if (res.size() - len < 20) throw std::system_error(api_error::not_enough_space);
		raw_set<uint16_t, std::endian::big>(res.data() + len, rr.serial);
		raw_set<uint16_t, std::endian::big>(res.data() + len + 4, rr.refresh);
		raw_set<uint16_t, std::endian::big>(res.data() + len + 8, rr.retry);
		raw_set<uint16_t, std::endian::big>(res.data() + len + 12, rr.expire);
		raw_set<uint16_t, std::endian::big>(res.data() + len + 16, rr.minimum);
		res.resize(len + 20);
		return res;
	}

	std::vector<uint8_t> build_srv(const srv_record& rr) {
		std::vector<uint8_t> res(6 + 256);
		if (rr.target.size() > 255) throw std::system_error(api_error::label_too_long);
		raw_set<uint16_t, std::endian::big>(res.data(), rr.priority);
		raw_set<uint16_t, std::endian::big>(res.data() + 2, rr.weight);
		raw_set<uint16_t, std::endian::big>(res.data() + 4, rr.port);
		std::error_code ec;
		auto len = convert_name(res.data() + 6, res.size() - 6, rr.target, ec);
		if (ec) throw std::system_error(ec);
		res.resize(6 + len);
		return res;
	}

	std::vector<uint8_t> build_tsig(const tsig_record& rr) {
		std::vector<uint8_t> res(256);
		if (rr.algorithm.size() > 255) throw std::system_error(api_error::label_too_long);
		std::error_code ec;
		auto len = convert_name(res.data(), res.size(), rr.algorithm, ec);
		if (ec) throw std::system_error(ec);
		res.resize(len + 10 + rr.mac.size() + rr.other.size());
		auto offset = len;
		uint64_t ts = std::chrono::system_clock::to_time_t(rr.timestamp);
		res[offset++] = ((ts >> 40) & 0xff);
		res[offset++] = ((ts >> 32) & 0xff);
		res[offset++] = ((ts >> 24) & 0xff);
		res[offset++] = ((ts >> 16) & 0xff);
		res[offset++] = ((ts >> 8) & 0xff);
		res[offset++] = (ts & 0xff);
		raw_set<uint16_t, std::endian::big>(res.data() + offset, rr.fudge);
		raw_set<uint16_t, std::endian::big>(res.data() + offset + 2, rr.mac.size());
		memcpy(res.data() + offset + 4, rr.mac.data(), rr.mac.size());
		raw_set<uint16_t, std::endian::big>(res.data() + offset + rr.mac.size() + 4, rr.original_id);
		raw_set<uint16_t, std::endian::big>(res.data() + offset + rr.mac.size() + 6, static_cast<uint16_t>(rr.error));
		raw_set<uint16_t, std::endian::big>(res.data() + offset + rr.mac.size() + 8, rr.other.size());
		memcpy(res.data() + offset + rr.mac.size() + 10, rr.other.data(), rr.other.size());
		return res;
	}

	std::vector<uint8_t> question::serialize() const {
		std::error_code ec;
		std::vector<uint8_t> record;
		record.resize(name.size() + (name.empty() ? 1 : 2) + 4);
		convert_name(record.data(), record.size() - 4, name, ec);
		if (ec) throw std::system_error(ec);
		auto ptr = record.data() + name.size() + (name.empty() ? 1 : 2);
		raw_set<uint16_t, std::endian::big>(ptr, static_cast<uint16_t>(qtype));
		raw_set<uint16_t, std::endian::big>(ptr + 2, static_cast<uint16_t>(qclass));
		return record;
	}

	const std::byte* question::parse(std::span<const std::byte> msg, const std::byte* const rr) {
		name.clear();
		const auto pmsg = msg.data();
		const auto pend = pmsg + msg.size();
		std::error_code ec;
		const auto pfixed = parse_label(msg, rr, name, ec);
		if (ec) throw std::system_error(ec);
		if (pfixed == nullptr || (pfixed + 4) > (pend)) throw std::runtime_error("invalid label");
		qtype = raw_get<dns::qtype, std::endian::big>(pfixed);
		qclass = raw_get<dns::qclass, std::endian::big>(pfixed + 2);
		return pfixed + 4;
	}

	std::vector<uint8_t> resource_record::serialize() const {
		std::error_code ec;
		std::vector<uint8_t> record;
		record.resize(name.size() + (name.empty() ? 1 : 2) + 10 + rdata.size());
		convert_name(record.data(), record.size() - (10 + rdata.size()), name, ec);
		if (ec) throw std::system_error(ec);
		auto ptr = record.data() + name.size() + (name.empty() ? 1 : 2);
		raw_set<qtype, std::endian::big>(ptr, rtype);
		raw_set<qclass, std::endian::big>(ptr + 2, rclass);
		raw_set<uint32_t, std::endian::big>(ptr + 4, ttl);
		raw_set<uint16_t, std::endian::big>(ptr + 8, rdata.size());
		memcpy(ptr + 10, rdata.data(), rdata.size());
		return record;
	}

	const std::byte* resource_record::parse(std::span<const std::byte> msg, const std::byte* const rr) {
		name.clear();
		const auto pmsg = msg.data();
		const auto pend = pmsg + msg.size();
		std::error_code ec;
		const auto pfixed = parse_label(msg, rr, name, ec);
		if (ec) throw std::system_error(ec);
		if (pfixed == nullptr || (pfixed + 10) > (pend)) throw std::runtime_error("invalid record");
		rtype = raw_get<qtype, std::endian::big>(pfixed);
		rclass = raw_get<qclass, std::endian::big>(pfixed + 2);
		ttl = raw_get<uint32_t, std::endian::big>(pfixed + 4);
		auto rdata_len = raw_get<uint16_t, std::endian::big>(pfixed + 8);
		if (pfixed + 10 + rdata_len > pend) throw std::runtime_error("invalid record");
		rdata.resize(rdata_len);
		memcpy(rdata.data(), pfixed + 10, rdata_len);
		return pfixed + 10 + rdata_len;
	}

	message_builder& message_builder::add_tsig_signature(std::string_view keyname, std::span<uint8_t> key) {
		std::array<uint8_t, max_message_size> tsigdata{};
		std::error_code ec;
		auto offset = convert_name(tsigdata.data(), tsigdata.size(), keyname, ec);
		assert(offset == 6);
		// Class (always any)
		tsigdata[offset++] = 0x00;
		tsigdata[offset++] = 0xff;
		// TTL (always 0)
		tsigdata[offset++] = 0x00;
		tsigdata[offset++] = 0x00;
		tsigdata[offset++] = 0x00;
		tsigdata[offset++] = 0x00;
		const size_t rr_offset = offset;
		// Algorithm name
		offset += convert_name(tsigdata.data() + offset, tsigdata.size() - offset, "hmac-md5.sig-alg.reg.int", ec);
		auto ts = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
		static_assert(sizeof(ts) >= 6);
		// Timestamp (48bit unix seconds)
		tsigdata[offset++] = (ts >> 40) & 0xff;
		tsigdata[offset++] = (ts >> 32) & 0xff;
		tsigdata[offset++] = (ts >> 24) & 0xff;
		tsigdata[offset++] = (ts >> 16) & 0xff;
		tsigdata[offset++] = (ts >> 8) & 0xff;
		tsigdata[offset++] = ts & 0xff;
		// Fudge
		tsigdata[offset++] = 0x01;
		tsigdata[offset++] = 0x2c;
		// Error (always 0 on request)
		tsigdata[offset++] = 0x00;
		tsigdata[offset++] = 0x00;
		// Other len (always 0 on request)
		tsigdata[offset++] = 0x00;
		tsigdata[offset++] = 0x00;

		// Signing with md5
		// TODO: Support for sha
		auto md = calculate_md5(key, std::span(m_start, bytes_used()), std::span(tsigdata.data(), offset));

		resource_record rr;
		rr.name = keyname;
		rr.rtype = qtype::tsig;
		rr.rclass = qclass::any;
		rr.ttl = 0;
		// Copy over the info from tsigdata
		rr.rdata.insert(rr.rdata.end(), tsigdata.data() + rr_offset, tsigdata.data() + offset - 4);
		// Mac size
		rr.rdata.push_back((md.size() >> 8) & 0xff);
		rr.rdata.push_back(md.size() & 0xff);
		// Mac
		rr.rdata.insert(rr.rdata.end(), md.data(), md.data() + md.size());
		// Original id
		rr.rdata.push_back(m_start[0]);
		rr.rdata.push_back(m_start[1]);
		// Error
		rr.rdata.push_back(0);
		rr.rdata.push_back(0);
		// Other len
		rr.rdata.push_back(0);
		rr.rdata.push_back(0);
		return add_additional(rr);
	}

	std::vector<uint8_t> message::serialize() const {
		std::vector<uint8_t> res;
		res.resize(std::numeric_limits<uint16_t>::max());
		serialize(res.data(), res.size());
		return res;
	}

	void message::serialize(void* buf, size_t bufsize) const {
		message_builder b(buf, bufsize);
		b.set_id(id);
		b.set_qr(is_response);
		b.set_authoritative(is_authoritative);
		b.set_truncated(is_truncated);
		b.set_recursion_desired(is_recursion_desired);
		b.set_recursion_available(is_recursion_available);
		b.set_opcode(opcode);
		b.set_rcode(rcode);
		for (auto& e : questions)
			b.add_question(e);
		for (auto& e : answers)
			b.add_answer(e);
		for (auto& e : authorities)
			b.add_authority(e);
		for (auto& e : additional)
			b.add_additional(e);
	}

	void message::parse(std::span<const std::byte> msg) {
		const auto pmsg = msg.data();
		const auto pend = pmsg + msg.size();
		if (msg.size() < 12) throw std::runtime_error("invalid message");
		id = raw_get<uint16_t, std::endian::big>(pmsg);
		is_response = static_cast<uint8_t>(pmsg[2]) & 0x80;
		opcode = static_cast<dns::opcode>((static_cast<uint8_t>(pmsg[2]) >> 3) & 0x0f);
		is_authoritative = static_cast<uint8_t>(pmsg[2]) & 0x04;
		is_truncated = static_cast<uint8_t>(pmsg[2]) & 0x02;
		is_recursion_desired = static_cast<uint8_t>(pmsg[2]) & 0x01;
		is_recursion_available = static_cast<uint8_t>(pmsg[3]) & 0x80;
		rcode = static_cast<dns::rcode>(static_cast<uint8_t>(pmsg[3]) & 0x0f);
		auto qcount = raw_get<uint16_t, std::endian::big>(pmsg + 4);
		auto answercount = raw_get<uint16_t, std::endian::big>(pmsg + 6);
		auto authoritycount = raw_get<uint16_t, std::endian::big>(pmsg + 8);
		auto additionalcount = raw_get<uint16_t, std::endian::big>(pmsg + 10);
		auto* ptr = pmsg + 12;
		questions.reserve(qcount);
		for (size_t i = 0; i < qcount; i++)
			ptr = questions.emplace_back().parse(msg, ptr);
		answers.reserve(answercount);
		for (size_t i = 0; i < answercount; i++)
			ptr = answers.emplace_back().parse(msg, ptr);
		authorities.reserve(authoritycount);
		for (size_t i = 0; i < authoritycount; i++)
			ptr = authorities.emplace_back().parse(msg, ptr);
		additional.reserve(additionalcount);
		for (size_t i = 0; i < additionalcount; i++)
			ptr = additional.emplace_back().parse(msg, ptr);
		if (ptr != pend) throw std::runtime_error("extra garbage after message");
	}

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
		case rcode::bad_signature: return s << "bad_signature";
		case rcode::bad_key: return s << "bad_key";
		case rcode::bad_time: return s << "bad_time";
		default: return s << static_cast<uint16_t>(r);
		}
	}

	std::ostream& operator<<(std::ostream& s, opcode o) {
		switch (o) {
		case opcode::query: return s << "QUERY";
		case opcode::iquery: return s << "IQUERY";
		case opcode::status: return s << "STATUS";
		case opcode::update: return s << "UPDATE";
		default: return s << static_cast<uint16_t>(o);
		}
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
		case qtype::ta: return s << "TA";
		case qtype::dlv: return s << "DLV";
		default: return s << static_cast<uint16_t>(t);
		}
	}

	std::ostream& operator<<(std::ostream& s, qclass c) {
		switch (c) {
		case qclass::in: return s << "IN";
		case qclass::csnet: return s << "CSNET";
		case qclass::chaos: return s << "CHAOS";
		case qclass::hs: return s << "HS";
		case qclass::any: return s << "ANY";
		default: return s << static_cast<uint16_t>(c);
		}
	}

	bool print_message_visitor::on_header(const message_header& hdr, asyncpp::io::const_buffer msg) noexcept {
		m_message = msg;
		m_is_update = hdr.opcode() == opcode::update;
		(*m_out) << ";; opcode: " << hdr.opcode() << ", status: " << hdr.rcode() << " id: " << hdr.id() << "\n";
		(*m_out) << ";; flags: ";
		if (hdr.qr()) (*m_out) << "qr ";
		if (hdr.authoritative()) (*m_out) << "aa ";
		if (hdr.truncated()) (*m_out) << "tc ";
		if (hdr.recursion_desired()) (*m_out) << "rd ";
		if (hdr.recursion_available()) (*m_out) << "ra ";
		(*m_out) << ", query: " << hdr.query_count() << ", answer: " << hdr.answer_count()
				 << ", authority: " << hdr.authoritative_count() << ", additional: " << hdr.additional_count() << "\n";
		return true;
	}

	bool print_message_visitor::on_question(std::string_view name, qtype qtype, qclass qclass) noexcept {
		if (!m_question_header_done) {
			if (m_is_update)
				(*m_out) << "\n;; ZONE SECTION:\n";
			else
				(*m_out) << "\n;; QUESTION SECTION:\n";
			m_question_header_done = true;
		}
		(*m_out) << name << "\t" << qclass << "\t" << qtype << "\n";
		return true;
	}

	bool print_message_visitor::on_answer(std::string_view name, qtype rtype, qclass rclass, uint32_t ttl,
										  std::span<const std::byte> rdata) noexcept {
		if (!m_answer_header_done) {
			if (m_is_update)
				(*m_out) << "\n;; PREREQUISITE SECTION:\n";
			else
				(*m_out) << "\n;; ANSWER SECTION:\n";
			m_answer_header_done = true;
		}
		print_rr(name, rtype, rclass, ttl, rdata);
		return true;
	}

	bool print_message_visitor::on_authority(std::string_view name, qtype rtype, qclass rclass, uint32_t ttl,
											 std::span<const std::byte> rdata) noexcept {
		if (!m_authority_header_done) {
			if (m_is_update)
				(*m_out) << "\n;; UPDATE SECTION:\n";
			else
				(*m_out) << "\n;; AUTHORITY SECTION:\n";
			m_authority_header_done = true;
		}
		print_rr(name, rtype, rclass, ttl, rdata);
		return true;
	}

	bool print_message_visitor::on_additional(std::string_view name, qtype rtype, qclass rclass, uint32_t ttl,
											  std::span<const std::byte> rdata) noexcept {
		if (!m_additional_header_done) {
			(*m_out) << "\n;; ADDITIONAL SECTION:\n";
			m_additional_header_done = true;
		}
		print_rr(name, rtype, rclass, ttl, rdata);
		return true;
	}

	void print_message_visitor::print_rr(std::string_view name, qtype rtype, qclass rclass, uint32_t ttl,
										 std::span<const std::byte> rdata) noexcept {
		(*m_out) << name << "\t" << rclass << "\t" << rtype << "\t" << ttl << "\t";
		std::error_code ec;
		switch (rtype) {
		case qtype::a:
			if (auto addr = parse_a(rdata, m_message, ec); !ec) (*m_out) << addr.to_string() << "\n";
			break;
		case qtype::aaaa:
			if (auto addr = parse_aaaa(rdata, m_message, ec); !ec) (*m_out) << addr.to_string() << "\n";
			break;
		case qtype::txt:
			if (auto txt = parse_txt(rdata, m_message, ec); !ec) (*m_out) << txt << "\n";
			break;
		case qtype::cname:
			if (auto cname = parse_cname(rdata, m_message, ec); !ec) (*m_out) << cname << "\n";
			break;
		case qtype::ns:
			if (auto ns = parse_ns(rdata, m_message, ec); !ec) (*m_out) << ns << "\n";
			break;
		case qtype::mx:
			if (auto mx = parse_mx(rdata, m_message, ec); !ec) (*m_out) << mx.preference << "\t" << mx.name << "\n";
			break;
		case qtype::ptr:
			if (auto ptr = parse_ptr(rdata, m_message, ec); !ec) (*m_out) << ptr << "\n";
			break;
		case qtype::soa:
			if (auto soa = parse_soa(rdata, m_message, ec); !ec)
				(*m_out) << soa.name << "\t" << soa.rname << "\t" << soa.serial << "\t" << soa.refresh << "\t"
						 << soa.retry << "\t" << soa.expire << "\t" << soa.minimum << "\n";
			break;
		case qtype::srv:
			if (auto srv = parse_srv(rdata, m_message, ec); !ec)
				(*m_out) << srv.priority << "\t" << srv.weight << "\t" << srv.port << "\t" << srv.target << "\n";
			break;
		case qtype::tsig:
			if (auto srv = parse_tsig(rdata, m_message, ec); !ec)
				(*m_out) << srv.algorithm << "\t" << std::chrono::system_clock::to_time_t(srv.timestamp) << "\t"
						 << srv.fudge << "\tmacsize=" << srv.mac.size() << "\t" << srv.original_id << "\t" << srv.error
						 << "\tothersize=" << srv.other.size() << "\n";
			break;
		default: (*m_out) << rdata.size() << " bytes\n";
		};
		if (ec) (*m_out) << rdata.size() << " bytes\n";
	}

	struct client::request {
		uint16_t id{};
		std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
		size_t tries{0};
		std::vector<std::byte> request_data{};
		std::function<void(api_error, const_buffer)> callback{};
		size_t send_count{};
	};

	client::client(asyncpp::io::io_service& service)
		: m_socket_ipv4(socket::create_udp(service, address_type::ipv4)),
		  m_socket_ipv6(socket::create_udp(service, address_type::ipv6)) {
		launch([](client* that) -> task<> {
			auto token = that->m_stop.get_token();
			std::array<std::byte, 64 * 1024> buf;
			while (!token.stop_requested()) {
				try {
					auto [size, src] = co_await that->m_socket_ipv4.recv_from(buf.data(), buf.size(), token);
					if (size < 12) continue;
					// TODO: Maybe check if src is a valid nameserver
					auto id = raw_get<uint16_t, std::endian::big>(buf.data());
					std::unique_lock lck{that->m_mutex};
					auto it = that->m_inflight.find(id);
					if (it == that->m_inflight.end()) continue;
					auto e = std::move(it->second);
					that->m_inflight.erase(it);
					lck.unlock();
					e.callback(api_error::ok, const_buffer(buf.data(), size));
				} catch (...) {}
			}
		}(this));
		launch([](client* that) -> task<> {
			auto token = that->m_stop.get_token();
			std::array<std::byte, 64 * 1024> buf;
			while (!token.stop_requested()) {
				try {
					auto [size, src] = co_await that->m_socket_ipv6.recv_from(buf.data(), buf.size(), token);
					if (size < 12) continue;
					// TODO: Maybe check if src is a valid nameserver
					auto id = raw_get<uint16_t, std::endian::big>(buf.data());
					std::unique_lock lck{that->m_mutex};
					auto it = that->m_inflight.find(id);
					if (it == that->m_inflight.end()) continue;
					auto e = std::move(it->second);
					that->m_inflight.erase(it);
					lck.unlock();
					e.callback(api_error::ok, const_buffer(buf.data(), size));
				} catch (...) {}
			}
		}(this));
		launch([](client* that) -> task<> {
			auto token = that->m_stop.get_token();
			auto wait_time = std::chrono::steady_clock::now() + that->m_timeout;
			while (!token.stop_requested()) {
				co_await timer::get_default().wait(wait_time, that->m_stop_timer.get_token());
				if (token.stop_requested()) break;
				auto now = std::chrono::steady_clock::now();
				wait_time = now + that->m_timeout;
				std::unique_lock lck{that->m_mutex};
				if (that->m_nameservers.empty()) continue;
				for (auto it = that->m_inflight.begin(); it != that->m_inflight.end();) {
					auto& e = it->second;
					if (now - e.start > that->m_timeout) {
						if (++e.tries > that->m_retries) {
							auto cb = std::move(e.callback);
							it = that->m_inflight.erase(it);
							lck.unlock();
							cb(api_error::timeout, {});
							lck.lock();
							continue;
						} else {
							e.start = now;
							that->send_requests(e);
						}
					}
					wait_time = (std::min)(wait_time, e.start + that->m_timeout);
					it++;
				}
			}
		}(this));
	}

	client::~client() { this->stop(); }

	void client::set_timeout(std::chrono::milliseconds timeout) {
		if (timeout.count() < 1) return;
		std::unique_lock lck{m_mutex};
		m_timeout = timeout;
		m_stop_timer.request_stop();
		m_stop_timer = {};
	}

	std::optional<uint16_t> client::get_free_id() const noexcept {
		std::unique_lock lck{m_mutex};
		if (m_inflight.size() == std::numeric_limits<uint16_t>::max() + 1) return std::nullopt;
		uint16_t id = rand();
		for (size_t i = 0; i < 10; i++) {
			if (!m_inflight.contains(id)) return id;
			id = rand();
		}
		// Fallback for a linear search for the first free id
		for (size_t i = 0; i <= std::numeric_limits<uint16_t>::max(); i++) {
			if (!m_inflight.contains(id)) return id;
		}
		// This shouldn't be possible
		return std::nullopt;
	}

	void client::query(asyncpp::io::const_buffer query, std::function<void(api_error, const_buffer)> callback) {
		if (query.size() < 12) {
			callback(api_error::incomplete_message, {});
			return;
		}
		std::unique_lock lck{m_mutex};
		request r;
		if (const auto origid = raw_get<uint16_t, std::endian::big>(query.data()); origid == 0) {
			auto found = get_free_id();
			if (!found) throw std::system_error(api_error::no_id);
			r.id = *found;
		} else if (m_inflight.contains(origid)) {
			throw std::system_error(api_error::duplicate_id);
		} else
			r.id = origid;

		r.callback = std::move(callback);
		r.request_data.resize(query.size());
		memcpy(r.request_data.data(), query.data(), query.size());
		raw_set<uint16_t, std::endian::big>(r.request_data.data(), r.id);
		r.send_count = m_nameservers.size();
		auto it = m_inflight.emplace(r.id, std::move(r)).first;

		send_requests(it->second);
	}

	void client::query(std::string_view name, dns::qtype qtype, dns::qclass qclass,
					   std::function<void(api_error, const_buffer)> callback) {
		std::array<std::byte, max_message_size> buffer;
		auto used = message_builder(buffer.data(), buffer.size())
						.set_opcode(opcode::query)
						.set_recursion_desired(true)
						.add_question(name, qtype, qclass)
						.bytes_used();
		query(asyncpp::io::const_buffer(buffer.data(), used), std::move(callback));
	}

	void client::send_requests(request& req) {
		req.send_count = m_nameservers.size();
		for (auto& e : m_nameservers) {
			auto sock = e.is_ipv6() ? &m_socket_ipv6 : &m_socket_ipv4;
			sock->send_to(
				req.request_data.data(), req.request_data.size(), e,
				[id = req.id, this](size_t, std::error_code ec) {
					std::unique_lock lck{m_mutex};
					auto it = m_inflight.find(id);
					if (it == m_inflight.end()) return;
					if (ec) {
						if (--it->second.send_count != 0) return;
						auto e = std::move(it->second);
						m_inflight.erase(it);
						lck.unlock();
						e.callback(api_error::internal, {});
						return;
					}
				},
				m_stop.get_token());
		}
		if (m_nameservers.empty()) {
			std::unique_lock lck{m_mutex};
			auto it = m_inflight.find(req.id);
			auto cb = std::move(it->second.callback);
			m_inflight.erase(it);
			lck.unlock();
			cb(api_error::internal, {});
		}
	}

	struct resolver {
		client* parent;
		std::string current_name;
		dns::qtype type;
		std::function<void(std::vector<address> res)> callback;
		size_t max_depth{10};

		void next() {
			std::array<std::byte, max_message_size> query;
			auto size = message_builder(query.data(), query.size())
							.set_opcode(opcode::query)
							.set_recursion_desired(true)
							.add_question(current_name, type, qclass::in)
							.bytes_used();
			parent->query(const_buffer(query.data(), size), [this](api_error error, const_buffer response) {
				if (error == api_error::ok) {
					std::vector<address> res;
					bool cname_found = false;
					try {
						visit_answer(response, [&](std::string_view rname, qtype rtype, qclass rclass, uint32_t ttl,
												   asyncpp::io::const_buffer rdata) {
							if (current_name != rname || rclass != qclass::in) return true;
							std::error_code ec;
							if (rtype == qtype::a) {
								auto rr = parse_a(rdata, response, ec);
								if (!ec) res.push_back(address(rr));
							} else if (rtype == qtype::aaaa) {
								auto rr = parse_aaaa(rdata, response, ec);
								if (!ec) res.push_back(address(rr));
							} else if (rtype == qtype::cname) {
								auto rr = parse_cname(rdata, response, ec);
								if (!ec) {
									current_name = std::move(rr);
									cname_found = true;
								}
							}
							return true;
						});
					} catch (...) {
						callback({});
						delete this;
						return;
					}
					max_depth--;
					// We found at least some ips
					if (cname_found && max_depth != 0) {
						// Nothing yet, retry with the cname name
						this->next();
						return;
					} else {
						// No results and no cname
						callback(std::move(res));
						delete this;
						return;
					}
				} else {
					callback({});
					delete this;
					return;
				}
			});
		}
	};

	void client::resolve(std::string name, dns::qtype type, std::function<void(std::vector<address> res)> callback) {
		auto res = new resolver{this, std::move(name), type, std::move(callback)};
		res->next();
	}

	void client::stop() {
		std::unique_lock lck{m_mutex};
		m_stop.request_stop();
		m_stop_timer.request_stop();
		for (auto& e : m_inflight) {
			e.second.callback(api_error::cancelled, {});
		}
	}
} // namespace asyncpp::io::dns
