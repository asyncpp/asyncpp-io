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

	class reader_rdata;

	class reader {
		std::span<const std::byte> m_message;
		std::array<std::byte, header_size> m_header;
		size_t m_answer_start;
		size_t m_authority_start;
		size_t m_additional_start;

		size_t skip_dname(size_t offset) const;

	public:
		template<typename TItBegin, typename TItEnd>
		struct iterator_wrapper {
			TItBegin m_begin;
			TItEnd m_end;

		public:
			iterator_wrapper(TItBegin beg, TItEnd end) : m_begin(beg), m_end(end) {}
			TItBegin begin() const { return m_begin; }
			TItEnd end() const { return m_end; }
		};
		class question;
		class question_iterator_end;
		class question_iterator;
		using rdata = reader_rdata;
		class record;
		class record_iterator_end;
		class record_iterator;

		explicit reader(std::span<const std::byte> msg);
		[[nodiscard]] uint16_t get_id() const noexcept;
		[[nodiscard]] bool get_qr() const noexcept;
		[[nodiscard]] opcode get_opcode() const noexcept;
		[[nodiscard]] bool get_aa() const noexcept;
		[[nodiscard]] bool get_tc() const noexcept;
		[[nodiscard]] bool get_rd() const noexcept;
		[[nodiscard]] bool get_ra() const noexcept;
		[[nodiscard]] bool get_answer_authenticated() const noexcept;
		[[nodiscard]] bool get_non_authenticated_data() const noexcept;
		[[nodiscard]] rcode get_rcode() const noexcept;

		[[nodiscard]] iterator_wrapper<question_iterator, question_iterator_end> questions() const;
		[[nodiscard]] question_iterator questions_begin() const;
		[[nodiscard]] question_iterator_end questions_end() const;
		[[nodiscard]] uint16_t questions_count() const noexcept;
		[[nodiscard]] iterator_wrapper<record_iterator, record_iterator_end> answers() const;
		[[nodiscard]] record_iterator answers_begin() const;
		[[nodiscard]] record_iterator_end answers_end() const;
		[[nodiscard]] uint16_t answers_count() const noexcept;
		[[nodiscard]] iterator_wrapper<record_iterator, record_iterator_end> authorities() const;
		[[nodiscard]] record_iterator authorities_begin() const;
		[[nodiscard]] record_iterator_end authorities_end() const;
		[[nodiscard]] uint16_t authorities_count() const noexcept;
		[[nodiscard]] iterator_wrapper<record_iterator, record_iterator_end> additionals() const;
		[[nodiscard]] record_iterator additionals_begin() const;
		[[nodiscard]] record_iterator_end additionals_end() const;
		[[nodiscard]] uint16_t additionals_count() const noexcept;

		void validate_tsig(qname keyname, tsig_algorithm alg, std::span<const std::byte> key,
						   std::chrono::system_clock::time_point now = std::chrono::system_clock::now());
		void remove_tsig();
	};

	class reader::question {
		qname m_name{};
		qtype m_type{};
		qclass m_class{};

	public:
		question() = default;
		question(const question&) = default;
		question(qname n, qtype t, qclass c) noexcept : m_name(n), m_type(t), m_class(c) {}
		question& operator=(const question&) = default;

		const qname& get_name() const noexcept { return m_name; }
		qtype get_type() const noexcept { return m_type; }
		qclass get_class() const noexcept { return m_class; }
	};

	class reader::question_iterator_end {};
	class reader::question_iterator {
		const std::span<const std::byte> m_message;
		const size_t m_question_end;
		size_t m_current_offset;
		size_t m_next_offset;
		question m_question{};

	public:
		question_iterator(std::span<const std::byte> msg, size_t start, size_t end)
			: m_message(msg), m_question_end(end), m_current_offset(start) {
			m_next_offset = m_current_offset;
			++(*this);
		}

		question_iterator& operator++() {
			m_current_offset = m_next_offset;
			if (m_next_offset >= m_question_end) return *this;
			auto name = qname::parse_from_msg(m_message, m_next_offset);
			if (m_next_offset + 4 > m_message.size()) throw std::runtime_error("invalid message");
			m_question = question(
				name, static_cast<qtype>(raw_get<uint16_t, std::endian::big>(m_message.data() + m_next_offset)),
				static_cast<qclass>(raw_get<uint16_t, std::endian::big>(m_message.data() + m_next_offset + 2)));
			m_next_offset += 4;
			return *this;
		}
		question_iterator operator++(int) {
			question_iterator retval = *this;
			++(*this);
			return retval;
		}
		bool operator==(question_iterator_end other) const { return m_current_offset >= m_question_end; }
		bool operator!=(question_iterator_end other) const { return !(*this == other); }
		const question& operator*() const { return m_question; }
		const question* operator->() const { return &m_question; }

		size_t offset() const noexcept { return m_current_offset; }
	};

	class reader_rdata {
		std::span<const std::byte> m_message{};
		std::span<const std::byte> m_rdata{};

	public:
		reader_rdata() = default;
		reader_rdata(std::span<const std::byte> msg, std::span<const std::byte> rdata)
			: m_message(msg), m_rdata(rdata) {
			if (m_rdata.data() < m_message.data() ||
				m_rdata.data() + m_rdata.size() > m_message.data() + m_message.size())
				throw std::invalid_argument("rdata outside message");
		}

		size_t remaining() const noexcept { return m_rdata.size(); }

		uint8_t pop_u8();
		uint16_t pop_u16();
		uint32_t pop_u24();
		uint32_t pop_u32();
		uint64_t pop_u40();
		uint64_t pop_u48();
		uint64_t pop_u56();
		uint64_t pop_u64();
		qname pop_domain_name();
		std::string_view pop_string();
		std::span<const std::byte> pop_raw(size_t len);
	};

	class reader::record {
		qname m_name{};
		qtype m_type{};
		qclass m_class{};
		std::chrono::seconds m_ttl{};
		rdata m_rdata{};

	public:
		record() = default;
		record(const record&) = default;
		record(qname n, qtype t, qclass c, std::chrono::seconds ttl, rdata rd) noexcept
			: m_name(n), m_type(t), m_class(c), m_ttl(ttl), m_rdata(rd) {}
		record& operator=(const record&) = default;

		const qname& get_name() const noexcept { return m_name; }
		qtype get_type() const noexcept { return m_type; }
		qclass get_class() const noexcept { return m_class; }
		std::chrono::seconds get_ttl() const noexcept { return m_ttl; }
		rdata get_rdata() const noexcept { return m_rdata; }

		template<qtype RType, qclass RClass = qclass::in>
			requires(!std::is_same_v<typename record_traits<RType, RClass>::rdata_type, void>)
		typename record_traits<RType, RClass>::rdata_type get_rdata() const;
	};

	class reader::record_iterator_end {};
	class reader::record_iterator {
		const std::span<const std::byte> m_message;
		const size_t m_section_end;
		size_t m_current_offset;
		size_t m_next_offset;
		record m_record{};

	public:
		record_iterator(std::span<const std::byte> msg, size_t start, size_t end)
			: m_message(msg), m_section_end(end), m_current_offset(start) {
			m_next_offset = m_current_offset;
			++(*this);
		}

		record_iterator& operator++() {
			m_current_offset = m_next_offset;
			if (m_next_offset >= m_section_end) return *this;
			auto name = qname::parse_from_msg(m_message, m_next_offset);
			if (m_next_offset + 10 > m_message.size()) throw std::runtime_error("invalid message");
			auto rdata_len = raw_get<uint16_t, std::endian::big>(m_message.data() + m_next_offset + 8);
			if (m_next_offset + 10 + rdata_len > m_message.size()) throw std::runtime_error("invalid message");

			m_record =
				record(name, static_cast<qtype>(raw_get<uint16_t, std::endian::big>(m_message.data() + m_next_offset)),
					   static_cast<qclass>(raw_get<uint16_t, std::endian::big>(m_message.data() + m_next_offset + 2)),
					   std::chrono::seconds(raw_get<uint32_t, std::endian::big>(m_message.data() + m_next_offset + 4)),
					   rdata(m_message, m_message.subspan(m_next_offset + 10, rdata_len)));
			m_next_offset += 10 + rdata_len;
			return *this;
		}
		record_iterator operator++(int) {
			record_iterator retval = *this;
			++(*this);
			return retval;
		}
		bool operator==(record_iterator_end other) const { return m_current_offset >= m_section_end; }
		bool operator!=(record_iterator_end other) const { return !(*this == other); }
		const record& operator*() const { return m_record; }
		const record* operator->() const { return &m_record; }

		size_t offset() const noexcept { return m_current_offset; }
	};

	inline size_t reader::skip_dname(size_t offset) const {
		if (offset >= m_message.size()) throw std::runtime_error("invalid message (domain name exceeds limits)");

		for (auto l = static_cast<uint8_t>(m_message[offset]); l != 0 && (l & 0xc0) == 0;
			 l = static_cast<uint8_t>(m_message[offset])) {
			offset += 1 + l;
			if (offset >= m_message.size()) throw std::runtime_error("invalid message (domain name exceeds limits)");
		}
		offset += ((static_cast<uint8_t>(m_message[offset]) & 0xc0) != 0) ? 2 : 1;
		return offset;
	}

	inline reader::reader(std::span<const std::byte> msg) : m_message(msg) {
		if (m_message.size() < header_size) throw std::runtime_error("invalid message");
		memcpy(m_header.data(), m_message.data(), header_size);
		auto offset = header_size;
		// Skip and verify query section
		for (size_t i = 0; i < questions_count(); i++) {
			offset = skip_dname(offset) + 4; // type & class
			if (offset > m_message.size()) throw std::runtime_error("truncated message");
		}
		m_answer_start = offset;
		// Skip and (partially) verify answers
		for (size_t i = 0; i < answers_count(); i++) {
			offset = skip_dname(offset) + 10; // type & class
			if (offset > m_message.size()) throw std::runtime_error("truncated message");
			auto rrlen = raw_get<uint16_t, std::endian::big>(m_message.data() + offset - 2);
			offset += rrlen;
			if (offset > m_message.size()) throw std::runtime_error("truncated message");
		}
		m_authority_start = offset;
		// Skip and (partially) verify authority section
		for (size_t i = 0; i < authorities_count(); i++) {
			offset = skip_dname(offset) + 10; // type & class
			if (offset > m_message.size()) throw std::runtime_error("truncated message");
			auto rrlen = raw_get<uint16_t, std::endian::big>(m_message.data() + offset - 2);
			offset += rrlen;
			if (offset > m_message.size()) throw std::runtime_error("truncated message");
		}
		m_additional_start = offset;
		// Skip and (partially) verify additional section
		for (size_t i = 0; i < additionals_count(); i++) {
			offset = skip_dname(offset) + 10; // type & class
			if (offset > m_message.size()) throw std::runtime_error("truncated message");
			auto rrlen = raw_get<uint16_t, std::endian::big>(m_message.data() + offset - 2);
			offset += rrlen;
			if (offset > m_message.size()) throw std::runtime_error("truncated message");
		}
		if (offset != m_message.size()) throw std::runtime_error("extra data at the end of message");
	}

	inline uint16_t reader::get_id() const noexcept { return raw_get<uint16_t, std::endian::big>(m_header.data()); }

	inline bool reader::get_qr() const noexcept { return (m_header[2] & static_cast<std::byte>(0x80)) != std::byte(); }

	inline opcode reader::get_opcode() const noexcept {
		return static_cast<opcode>((m_header[2] & static_cast<std::byte>(0x78)) >> 3);
	}

	inline bool reader::get_aa() const noexcept { return (m_header[2] & static_cast<std::byte>(0x04)) != std::byte(); }

	inline bool reader::get_tc() const noexcept { return (m_header[2] & static_cast<std::byte>(0x02)) != std::byte(); }

	inline bool reader::get_rd() const noexcept { return (m_header[2] & static_cast<std::byte>(0x01)) != std::byte(); }

	inline bool reader::get_ra() const noexcept { return (m_header[3] & static_cast<std::byte>(0x80)) != std::byte(); }

	inline bool reader::get_answer_authenticated() const noexcept {
		return (m_header[3] & static_cast<std::byte>(0x20)) != std::byte();
	}

	inline bool reader::get_non_authenticated_data() const noexcept {
		return (m_header[3] & static_cast<std::byte>(0x10)) != std::byte();
	}

	inline rcode reader::get_rcode() const noexcept {
		return static_cast<rcode>(m_header[3] & static_cast<std::byte>(0x0f));
	}

	inline reader::iterator_wrapper<reader::question_iterator, reader::question_iterator_end>
	reader::questions() const {
		return {question_iterator(m_message, header_size, m_answer_start), question_iterator_end{}};
	}

	inline reader::question_iterator reader::questions_begin() const {
		return question_iterator(m_message, header_size, m_answer_start);
	}

	inline reader::question_iterator_end reader::questions_end() const { return question_iterator_end{}; }

	inline uint16_t reader::questions_count() const noexcept {
		return raw_get<uint16_t, std::endian::big>(m_header.data() + 4);
	}

	inline reader::iterator_wrapper<reader::record_iterator, reader::record_iterator_end> reader::answers() const {
		return {record_iterator(m_message, m_answer_start, m_authority_start), record_iterator_end{}};
	}

	inline reader::record_iterator reader::answers_begin() const {
		return record_iterator(m_message, m_answer_start, m_authority_start);
	}

	inline reader::record_iterator_end reader::answers_end() const { return record_iterator_end{}; }

	inline uint16_t reader::answers_count() const noexcept {
		return raw_get<uint16_t, std::endian::big>(m_header.data() + 6);
	}

	inline reader::iterator_wrapper<reader::record_iterator, reader::record_iterator_end> reader::authorities() const {
		return {record_iterator(m_message, m_authority_start, m_additional_start), record_iterator_end{}};
	}

	inline reader::record_iterator reader::authorities_begin() const {
		return record_iterator(m_message, m_authority_start, m_additional_start);
	}

	inline reader::record_iterator_end reader::authorities_end() const { return record_iterator_end{}; }

	inline uint16_t reader::authorities_count() const noexcept {
		return raw_get<uint16_t, std::endian::big>(m_header.data() + 8);
	}

	inline reader::iterator_wrapper<reader::record_iterator, reader::record_iterator_end> reader::additionals() const {
		return {record_iterator(m_message, m_additional_start, m_message.size()), record_iterator_end{}};
	}

	inline reader::record_iterator reader::additionals_begin() const {
		return record_iterator(m_message, m_additional_start, m_message.size());
	}

	inline reader::record_iterator_end reader::additionals_end() const { return record_iterator_end{}; }

	inline uint16_t reader::additionals_count() const noexcept {
		return raw_get<uint16_t, std::endian::big>(m_header.data() + 10);
	}

	inline uint8_t reader::rdata::pop_u8() {
		if (m_rdata.size() < 1) throw std::out_of_range("rdata too small");
		auto res = static_cast<uint8_t>(m_rdata[0]);
		m_rdata = m_rdata.subspan(1);
		return res;
	}

	inline uint16_t reader::rdata::pop_u16() {
		if (m_rdata.size() < 2) throw std::out_of_range("rdata too small");
		auto res = raw_get<uint16_t, std::endian::big>(m_rdata.data());
		m_rdata = m_rdata.subspan(2);
		return res;
	}

	inline uint32_t reader::rdata::pop_u24() {
		if (m_rdata.size() < 3) throw std::out_of_range("rdata too small");
		std::array<std::byte, 4> be{};
		memcpy(be.data() + 1, m_rdata.data(), 3);
		auto res = raw_get<uint32_t, std::endian::big>(be.data());
		m_rdata = m_rdata.subspan(3);
		return res;
	}

	inline uint32_t reader::rdata::pop_u32() {
		if (m_rdata.size() < 4) throw std::out_of_range("rdata too small");
		auto res = raw_get<uint32_t, std::endian::big>(m_rdata.data());
		m_rdata = m_rdata.subspan(4);
		return res;
	}

	inline uint64_t reader::rdata::pop_u40() {
		if (m_rdata.size() < 5) throw std::out_of_range("rdata too small");
		std::array<std::byte, 8> be{};
		memcpy(be.data() + 3, m_rdata.data(), 5);
		auto res = raw_get<uint64_t, std::endian::big>(be.data());
		m_rdata = m_rdata.subspan(5);
		return res;
	}

	inline uint64_t reader::rdata::pop_u48() {
		if (m_rdata.size() < 6) throw std::out_of_range("rdata too small");
		std::array<std::byte, 8> be{};
		memcpy(be.data() + 2, m_rdata.data(), 6);
		auto res = raw_get<uint64_t, std::endian::big>(be.data());
		m_rdata = m_rdata.subspan(6);
		return res;
	}

	inline uint64_t reader::rdata::pop_u56() {
		if (m_rdata.size() < 7) throw std::out_of_range("rdata too small");
		std::array<std::byte, 8> be{};
		memcpy(be.data() + 1, m_rdata.data(), 7);
		auto res = raw_get<uint64_t, std::endian::big>(be.data());
		m_rdata = m_rdata.subspan(7);
		return res;
	}

	inline uint64_t reader::rdata::pop_u64() {
		if (m_rdata.size() < 8) throw std::out_of_range("rdata too small");
		auto res = raw_get<uint64_t, std::endian::big>(m_rdata.data());
		m_rdata = m_rdata.subspan(8);
		return res;
	}

	inline qname reader::rdata::pop_domain_name() {
		size_t offset = m_rdata.data() - m_message.data();
		auto res = qname::parse_from_msg(m_message, offset);
		m_rdata = m_rdata.subspan(offset - (m_rdata.data() - m_message.data()));
		return res;
	}

	inline std::string_view reader::rdata::pop_string() {
		auto len = pop_u8();
		auto data = pop_raw(len);
		return std::string_view(reinterpret_cast<const char*>(data.data()), data.size());
	}

	inline std::span<const std::byte> reader::rdata::pop_raw(size_t len) {
		if (m_rdata.size() < len) throw std::out_of_range("rdata too small");
		auto res = m_rdata.subspan(0, len);
		m_rdata = m_rdata.subspan(len);
		return res;
	}

	template<qtype RType, qclass RClass>
		requires(!std::is_same_v<typename record_traits<RType, RClass>::rdata_type, void>)
	typename record_traits<RType, RClass>::rdata_type reader::record::get_rdata() const {
		if (this->get_type() != RType || this->get_class() != RClass) throw std::runtime_error("invalid record type");
		auto data = this->get_rdata();
		typename record_traits<RType, RClass>::rdata_type res{};
		record_traits<RType, RClass>::parse(res, data);
		return res;
	}

} // namespace asyncpp::io::dns
