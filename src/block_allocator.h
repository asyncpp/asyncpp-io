#pragma once
#include <asyncpp/detail/sanitizers.h>

#include <array>
#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <mutex>

namespace asyncpp::io::detail {

	template<typename T, typename TMutex = std::mutex>
	class block_allocator {

		struct page {
			page* next_page{};
			uint64_t usage{};
			alignas(T) std::array<std::byte, sizeof(T) * 64> storage{};
		};

		TMutex m_mtx{};
		page* m_first_page{};

	public:
		constexpr block_allocator() noexcept = default;
		block_allocator(const block_allocator&) = delete;
		block_allocator& operator=(const block_allocator&) = delete;
		~block_allocator() noexcept {
			auto p = m_first_page;
			while (p != nullptr) {
				auto ptr = p;
				p = p->next_page;
				assert(ptr->usage == 0);
				delete ptr;
			}
		}
		void* allocate() noexcept {
			std::unique_lock lck{m_mtx};
			page* p = m_first_page;
			page** page_ptr = &m_first_page;
			while (p != nullptr) {
				if (p->usage != std::numeric_limits<uint64_t>::max()) {
					auto free_block = std::countr_one(p->usage);
					assert(free_block < 64 && free_block >= 0);
					p->usage |= (static_cast<uint64_t>(1) << free_block);
#if ASYNCPP_HAS_ASAN
					__asan_unpoison_memory_region(p->storage.data() + sizeof(T) * free_block, sizeof(T));
#endif
					return p->storage.data() + sizeof(T) * free_block;
				}
				page_ptr = &p->next_page;
				p = p->next_page;
			}
			// No free blocks left
			p = *page_ptr = new (std::nothrow) page{};
			if (p == nullptr) return nullptr;
			p->usage |= 1;
#if ASYNCPP_HAS_ASAN
			__asan_poison_memory_region(p->storage.data() + sizeof(T), p->storage.size() - sizeof(T));
#endif
			return p->storage.data();
		}
		void deallocate(void* ptr) noexcept {
			std::unique_lock lck{m_mtx};
			page* p = m_first_page;
			while (p != nullptr) {
				if (ptr >= p->storage.data() && ptr < p->storage.data() + p->storage.size()) {
#if ASYNCPP_HAS_ASAN
					__asan_poison_memory_region(ptr, sizeof(T));
#endif
					const auto offset = static_cast<const std::byte*>(ptr) - p->storage.data();
					assert(offset % sizeof(T) == 0);
					assert(offset < sizeof(T) * 64);
					const auto idx = offset / sizeof(T);
					assert((p->usage & static_cast<uint64_t>(1) << idx) != 0);
					p->usage &= ~(static_cast<uint64_t>(1) << idx);
					return;
				}
				p = p->next_page;
			}
		}
		template<typename... Args>
		T* create(Args&&... args) {
			auto ptr = allocate();
			if (ptr == nullptr) return nullptr;
			if constexpr (std::is_nothrow_constructible_v<T, Args&&...>) {
				return new (ptr) T(std::forward<Args>(args)...);
			} else {
				try {
					return new (ptr) T(std::forward<Args>(args)...);
				} catch (...) {
					this->deallocate(ptr);
					throw;
				}
			}
			// unreachable
		}
		void destroy(T* obj) {
			if (obj != nullptr) {
				obj->~T();
				this->deallocate(obj);
			}
		}
	};
} // namespace asyncpp::io::detail
