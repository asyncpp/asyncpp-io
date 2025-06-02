#pragma once
#include <asyncpp/io/buffer.h>
#include <asyncpp/io/dns/enums.h>
#include <asyncpp/io/dns/qname.h>

#include <chrono>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <string_view>

namespace asyncpp::io::dns {
	template<qtype RType, qclass RClass>
	struct record_traits;

	class writer {
		std::array<std::byte, max_message_size> m_message;
		size_t m_current_offset{header_size};
		size_t m_rr_offset{0};
		// 0 => query, 1 => answer, 2 => authority, 3 => additional
		uint8_t m_current_section{0};
		qname::compression_table m_rname_compression;

	public:
		writer() noexcept;
		// Manipulate header
		writer& set_id(uint16_t id) noexcept;
		writer& set_qr(bool qr) noexcept;
		writer& set_opcode(opcode op) noexcept;
		writer& set_aa(bool aa) noexcept;
		writer& set_tc(bool tc) noexcept;
		writer& set_rd(bool rd) noexcept;
		writer& set_ra(bool ra) noexcept;
		writer& set_answer_authenticated(bool aa) noexcept;
		writer& set_non_authenticated_data(bool nad) noexcept;
		writer& set_rcode(rcode code) noexcept;

		// Manipulate body
		writer& add_query(qname name, qtype t, qclass c);
		writer& rr_begin_answer(qname name, qtype t, qclass c, std::chrono::seconds ttl);
		writer& rr_begin_authority(qname name, qtype t, qclass c, std::chrono::seconds ttl);
		writer& rr_begin_additional(qname name, qtype t, qclass c, std::chrono::seconds ttl);
		writer& rr_put_u8(uint8_t val);
		writer& rr_put_u16(uint16_t val);
		writer& rr_put_u24(uint32_t val);
		writer& rr_put_u32(uint32_t val);
		writer& rr_put_u40(uint64_t val);
		writer& rr_put_u48(uint64_t val);
		writer& rr_put_u56(uint64_t val);
		writer& rr_put_u64(uint64_t val);
		writer& rr_put_domain_name(qname val, bool allow_compression = true);
		writer& rr_put_string(std::string_view val);
		writer& rr_put_raw(std::span<const std::byte> val);
		writer& rr_end() noexcept;

		template<qtype RType, qclass RClass = qclass::in>
			requires(!std::is_same_v<typename record_traits<RType, RClass>::rdata_type, void>)
		writer& rr_add_answer(qname name, const typename record_traits<RType, RClass>::rdata_type& rdata,
							  std::chrono::seconds ttl = std::chrono::seconds{3600});
		template<qtype RType, qclass RClass = qclass::in>
			requires(!std::is_same_v<typename record_traits<RType, RClass>::rdata_type, void>)
		writer& rr_add_authority(qname name, const typename record_traits<RType, RClass>::rdata_type& rdata,
								 std::chrono::seconds ttl = std::chrono::seconds{3600});
		template<qtype RType, qclass RClass = qclass::in>
			requires(!std::is_same_v<typename record_traits<RType, RClass>::rdata_type, void>)
		writer& rr_add_additional(qname name, const typename record_traits<RType, RClass>::rdata_type& rdata,
								  std::chrono::seconds ttl = std::chrono::seconds{3600});

		writer& sign_tsig(qname keyname, tsig_algorithm alg, std::span<const std::byte> key, uint16_t error = 0,
						  std::span<const std::byte> otherdata = {},
						  std::chrono::system_clock::time_point ts = std::chrono::system_clock::now(),
						  std::chrono::seconds fudge = std::chrono::seconds{300});

		size_t size() const noexcept;
		size_t build_into(std::span<std::byte> buffer) const noexcept;
		std::vector<std::byte> build() const;
	};

	inline writer::writer() noexcept {
		// Clear out the header
		for (size_t i = 0; i < m_current_offset; i++)
			m_message[i] = std::byte{};
	}

	inline writer& writer::set_id(uint16_t id) noexcept {
		raw_set<uint16_t, std::endian::big>(m_message.data(), id);
		return *this;
	}

	inline writer& writer::set_qr(bool qr) noexcept {
		m_message[2] &= ~static_cast<std::byte>(0x80);
		m_message[2] |= static_cast<std::byte>(qr ? 0x80 : 0);
		return *this;
	}

	inline writer& writer::set_opcode(opcode op) noexcept {
		m_message[2] &= ~static_cast<std::byte>(0x78);
		m_message[2] |= static_cast<std::byte>(op) << 3;
		return *this;
	}

	inline writer& writer::set_aa(bool aa) noexcept {
		m_message[2] &= ~static_cast<std::byte>(0x04);
		m_message[2] |= static_cast<std::byte>(aa ? 0x04 : 0);
		return *this;
	}

	inline writer& writer::set_tc(bool tc) noexcept {
		m_message[2] &= ~static_cast<std::byte>(0x02);
		m_message[2] |= static_cast<std::byte>(tc ? 0x02 : 0);
		return *this;
	}

	inline writer& writer::set_rd(bool rd) noexcept {
		m_message[2] &= ~static_cast<std::byte>(0x01);
		m_message[2] |= static_cast<std::byte>(rd ? 0x01 : 0);
		return *this;
	}

	inline writer& writer::set_ra(bool ra) noexcept {
		m_message[3] &= ~static_cast<std::byte>(0x80);
		m_message[3] |= static_cast<std::byte>(ra ? 0x80 : 0);
		return *this;
	}

	inline writer& writer::set_answer_authenticated(bool aa) noexcept {
		m_message[3] &= ~static_cast<std::byte>(0x20);
		m_message[3] |= static_cast<std::byte>(aa ? 0x20 : 0);
		return *this;
	}

	inline writer& writer::set_non_authenticated_data(bool nad) noexcept {
		m_message[3] &= ~static_cast<std::byte>(0x10);
		m_message[3] |= static_cast<std::byte>(nad ? 0x10 : 0);
		return *this;
	}

	inline writer& writer::set_rcode(rcode code) noexcept {
		m_message[3] &= ~static_cast<std::byte>(0x0f);
		m_message[3] |= static_cast<std::byte>(code);
		return *this;
	}

	inline writer& writer::add_query(qname name, qtype t, qclass c) {
		if (m_current_section > 0) throw std::logic_error("invalid section order");
		const auto checkpoint = m_current_offset;
		if ((m_current_offset = name.serialize_to_msg(m_message, m_current_offset, &m_rname_compression)) == 0 ||
			4 > (m_message.size() - m_current_offset)) {
			m_current_offset = checkpoint;
			throw std::out_of_range("query exceeds message size");
		}
		raw_set<uint16_t, std::endian::big>(m_message.data() + m_current_offset, static_cast<uint16_t>(t));
		raw_set<uint16_t, std::endian::big>(m_message.data() + m_current_offset + 2, static_cast<uint16_t>(c));
		m_current_offset += 4;
		const auto nqueries = raw_get<uint16_t, std::endian::big>(m_message.data() + 4);
		raw_set<uint16_t, std::endian::big>(m_message.data() + 4, nqueries + 1);
		return *this;
	}

	inline writer& writer::rr_begin_answer(qname name, qtype t, qclass c, std::chrono::seconds ttl) {
		if (m_current_section > 1) throw std::logic_error("invalid section order");
		m_current_section = 1;
		if (m_rr_offset != 0) rr_end();
		const auto checkpoint = m_current_offset;
		if ((m_current_offset = name.serialize_to_msg(m_message, m_current_offset, &m_rname_compression)) == 0 ||
			10 > (m_message.size() - m_current_offset)) {
			m_current_offset = checkpoint;
			throw std::out_of_range("query exceeds message size");
		}
		raw_set<uint16_t, std::endian::big>(m_message.data() + m_current_offset, static_cast<uint16_t>(t));
		raw_set<uint16_t, std::endian::big>(m_message.data() + m_current_offset + 2, static_cast<uint16_t>(c));
		raw_set<uint32_t, std::endian::big>(m_message.data() + m_current_offset + 4,
											static_cast<uint32_t>(ttl.count()));
		raw_set<uint16_t, std::endian::big>(m_message.data() + m_current_offset + 8, 0);
		m_current_offset += 10;
		m_rr_offset = m_current_offset;
		const auto nqueries = raw_get<uint16_t, std::endian::big>(m_message.data() + 6);
		raw_set<uint16_t, std::endian::big>(m_message.data() + 6, nqueries + 1);
		return *this;
	}

	inline writer& writer::rr_begin_authority(qname name, qtype t, qclass c, std::chrono::seconds ttl) {

		if (m_current_section > 2) throw std::logic_error("invalid section order");
		m_current_section = 2;
		if (m_rr_offset != 0) rr_end();
		const auto checkpoint = m_current_offset;
		if ((m_current_offset = name.serialize_to_msg(m_message, m_current_offset, &m_rname_compression)) == 0 ||
			10 > (m_message.size() - m_current_offset)) {
			m_current_offset = checkpoint;
			throw std::out_of_range("query exceeds message size");
		}
		raw_set<uint16_t, std::endian::big>(m_message.data() + m_current_offset, static_cast<uint16_t>(t));
		raw_set<uint16_t, std::endian::big>(m_message.data() + m_current_offset + 2, static_cast<uint16_t>(c));
		raw_set<uint32_t, std::endian::big>(m_message.data() + m_current_offset + 4,
											static_cast<uint32_t>(ttl.count()));
		raw_set<uint16_t, std::endian::big>(m_message.data() + m_current_offset + 8, 0);
		m_current_offset += 10;
		m_rr_offset = m_current_offset;
		const auto nqueries = raw_get<uint16_t, std::endian::big>(m_message.data() + 8);
		raw_set<uint16_t, std::endian::big>(m_message.data() + 8, nqueries + 1);
		return *this;
	}

	inline writer& writer::rr_begin_additional(qname name, qtype t, qclass c, std::chrono::seconds ttl) {
		if (m_rr_offset != 0) rr_end();
		m_current_section = 3;
		const auto checkpoint = m_current_offset;
		if ((m_current_offset = name.serialize_to_msg(m_message, m_current_offset, &m_rname_compression)) == 0 ||
			10 > (m_message.size() - m_current_offset)) {
			m_current_offset = checkpoint;
			throw std::out_of_range("query exceeds message size");
		}
		raw_set<uint16_t, std::endian::big>(m_message.data() + m_current_offset, static_cast<uint16_t>(t));
		raw_set<uint16_t, std::endian::big>(m_message.data() + m_current_offset + 2, static_cast<uint16_t>(c));
		raw_set<uint32_t, std::endian::big>(m_message.data() + m_current_offset + 4,
											static_cast<uint32_t>(ttl.count()));
		raw_set<uint16_t, std::endian::big>(m_message.data() + m_current_offset + 8, 0);
		m_current_offset += 10;
		m_rr_offset = m_current_offset;
		const auto nqueries = raw_get<uint16_t, std::endian::big>(m_message.data() + 10);
		raw_set<uint16_t, std::endian::big>(m_message.data() + 10, nqueries + 1);
		return *this;
	}

	inline writer& writer::rr_put_u8(uint8_t val) {
		if (1 > (m_message.size() - m_current_offset)) throw std::out_of_range("query exceeds message size");
		m_message[m_current_offset++] = static_cast<std::byte>(val);
		return *this;
	}

	inline writer& writer::rr_put_u16(uint16_t val) {
		if (2 > (m_message.size() - m_current_offset)) throw std::out_of_range("query exceeds message size");
		raw_set<uint16_t, std::endian::big>(m_message.data() + m_current_offset, val);
		m_current_offset += 2;
		return *this;
	}

	inline writer& writer::rr_put_u24(uint32_t val) {
		std::array<std::byte, 4> be;
		if (3 > (m_message.size() - m_current_offset)) throw std::out_of_range("query exceeds message size");
		raw_set<uint32_t, std::endian::big>(be.data(), val);
		memcpy(m_message.data() + m_current_offset, be.data() + 1, 3);
		m_current_offset += 3;
		return *this;
	}

	inline writer& writer::rr_put_u32(uint32_t val) {
		if (4 > (m_message.size() - m_current_offset)) throw std::out_of_range("query exceeds message size");
		raw_set<uint32_t, std::endian::big>(m_message.data() + m_current_offset, val);
		m_current_offset += 4;
		return *this;
	}

	inline writer& writer::rr_put_u40(uint64_t val) {
		std::array<std::byte, 8> be;
		if (5 > (m_message.size() - m_current_offset)) throw std::out_of_range("query exceeds message size");
		raw_set<uint64_t, std::endian::big>(be.data(), val);
		memcpy(m_message.data() + m_current_offset, be.data() + 3, 5);
		m_current_offset += 5;
		return *this;
	}

	inline writer& writer::rr_put_u48(uint64_t val) {
		std::array<std::byte, 8> be;
		if (6 > (m_message.size() - m_current_offset)) throw std::out_of_range("query exceeds message size");
		raw_set<uint64_t, std::endian::big>(be.data(), val);
		memcpy(m_message.data() + m_current_offset, be.data() + 2, 6);
		m_current_offset += 6;
		return *this;
	}

	inline writer& writer::rr_put_u56(uint64_t val) {
		std::array<std::byte, 8> be;
		if (7 > (m_message.size() - m_current_offset)) throw std::out_of_range("query exceeds message size");
		raw_set<uint64_t, std::endian::big>(be.data(), val);
		memcpy(m_message.data() + m_current_offset, be.data() + 1, 7);
		m_current_offset += 7;
		return *this;
	}

	inline writer& writer::rr_put_u64(uint64_t val) {
		if (8 > (m_message.size() - m_current_offset)) throw std::out_of_range("query exceeds message size");
		raw_set<uint64_t, std::endian::big>(m_message.data() + m_current_offset, val);
		m_current_offset += 8;
		return *this;
	}

	inline writer& writer::rr_put_domain_name(qname val, bool allow_compression) {
		auto res =
			val.serialize_to_msg(m_message, m_current_offset, allow_compression ? &m_rname_compression : nullptr);
		if (res == 0) throw std::out_of_range("query exceeds message size");
		m_current_offset = res;
		return *this;
	}

	inline writer& writer::rr_put_string(std::string_view val) {
		if (val.size() > 255) throw std::logic_error("string exceeds maximum string length");
		if ((1 + val.size()) > (m_message.size() - m_current_offset))
			throw std::out_of_range("query exceeds message size");
		m_message[m_current_offset++] = static_cast<std::byte>(val.size());
		for (auto e : val)
			m_message[m_current_offset++] = static_cast<std::byte>(e);
		return *this;
	}

	inline writer& writer::rr_put_raw(std::span<const std::byte> val) {
		if (val.size() > (m_message.size() - m_current_offset)) throw std::out_of_range("query exceeds message size");
		for (auto e : val)
			m_message[m_current_offset++] = static_cast<std::byte>(e);
		return *this;
	}

	inline writer& writer::rr_end() noexcept {
		if (m_rr_offset == 0) return *this;
		const auto len = m_current_offset - m_rr_offset;
		raw_set<uint16_t, std::endian::big>(m_message.data() + (m_rr_offset - 2), len);
		m_rr_offset = 0;
		return *this;
	}

	template<qtype RType, qclass RClass>
		requires(!std::is_same_v<typename record_traits<RType, RClass>::rdata_type, void>)
	inline writer& writer::rr_add_answer(qname name, const typename record_traits<RType, RClass>::rdata_type& rdata,
										 std::chrono::seconds ttl) {
		this->rr_begin_answer(name, RType, RClass, ttl);
		record_traits<RType, RClass>::serialize(rdata, *this);
		return rr_end();
	}
	template<qtype RType, qclass RClass>
		requires(!std::is_same_v<typename record_traits<RType, RClass>::rdata_type, void>)
	inline writer& writer::rr_add_authority(qname name, const typename record_traits<RType, RClass>::rdata_type& rdata,
											std::chrono::seconds ttl) {
		this->rr_begin_authority(name, RType, RClass, ttl);
		record_traits<RType, RClass>::serialize(rdata, *this);
		return rr_end();
	}
	template<qtype RType, qclass RClass>
		requires(!std::is_same_v<typename record_traits<RType, RClass>::rdata_type, void>)
	inline writer& writer::rr_add_additional(qname name, const typename record_traits<RType, RClass>::rdata_type& rdata,
											 std::chrono::seconds ttl) {
		this->rr_begin_additional(name, RType, RClass, ttl);
		record_traits<RType, RClass>::serialize(rdata, *this);
		return rr_end();
	}

	inline size_t writer::size() const noexcept { return m_current_offset; }

	inline size_t writer::build_into(std::span<std::byte> buffer) const noexcept {
		const auto len = std::min(buffer.size(), m_current_offset);
		for (size_t i = 0; i < len; i++) {
			buffer[i] = m_message[i];
		}
		return m_current_offset;
	}

	inline std::vector<std::byte> writer::build() const {
		std::vector<std::byte> res(size());
		res.resize(build_into(res));
		return res;
	}

} // namespace asyncpp::io::dns
