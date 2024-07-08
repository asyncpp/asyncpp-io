#include <asyncpp/io/file.h>
#include <asyncpp/io/io_service.h>
#include <asyncpp/launch.h>
#include <asyncpp/task.h>

#include <gtest/gtest.h>

using namespace asyncpp;

namespace {
	std::string read_file(const std::string& name) {
		std::ifstream file(name, std::ios::in | std::ios::binary);
		if (!file) throw std::runtime_error("failed to open file");
		std::ostringstream ss;
		ss << file.rdbuf();
		return ss.str();
	}
} // namespace

#if ASYNCPP_IO_HANDLE_FROM_FILEBUF
TEST(ASYNCPP_IO, FileFreeGetHandle) {
	std::ofstream file("test.bin", std::ios::binary | std::ios::trunc);
	auto hdl = io::detail::get_file_handle_from_filebuf(file.rdbuf());
	ASSERT_GE(hdl, 3);
}

TEST(ASYNCPP_IO, FileFreeRead) {
	std::fstream file("test.bin", std::ios_base::in | std::ios_base::out | std::ios::binary | std::ios::trunc);
	ASSERT_TRUE(file);
	ASSERT_TRUE(file.write("Hello World", 11));
	ASSERT_TRUE(file.flush());

	io::io_service service;
	std::string read;
	async_launch_scope scope;
	scope.invoke([&service, &file, &read]() -> task<> {
		read.resize(128);
		auto hdl = io::detail::get_file_handle_from_filebuf(file.rdbuf());
		auto size = co_await io::read(*service.engine(), hdl, read.data(), read.size(), 0);
		read.resize(size);
		service.stop();
	});

	service.run();

	ASSERT_TRUE(scope.all_done());
	ASSERT_EQ(read.size(), 11);
	ASSERT_EQ(read, "Hello World");
}

TEST(ASYNCPP_IO, FileFreeWrite) {
	std::fstream file("test.bin", std::ios_base::in | std::ios_base::out | std::ios::binary | std::ios::trunc);
	ASSERT_TRUE(file);

	io::io_service service;
	size_t write_size;
	async_launch_scope scope;
	scope.invoke([&service, &file, &write_size]() -> task<> {
		auto hdl = io::detail::get_file_handle_from_filebuf(file.rdbuf());
		write_size = co_await io::write(*service.engine(), hdl, "Hello World", 11, 0);
		service.stop();
	});

	service.run();

	ASSERT_EQ(write_size, 11);

	ASSERT_TRUE(scope.all_done());
	std::string read(128, '\0');
	ASSERT_EQ(file.read(read.data(), read.size()).gcount(), 11);
	read.resize(11);
	ASSERT_EQ(read, "Hello World");
}
#endif

TEST(ASYNCPP_IO, FileCreate) {
	io::io_service service;

	{
		io::file file(service, "test.bin", std::ios_base::in | std::ios_base::out | std::ios::binary | std::ios::trunc);
		ASSERT_TRUE(file.is_open());
		ASSERT_TRUE(file);
		ASSERT_FALSE(!file);
	}
	{
		io::file file(service, std::string("test.bin"),
					  std::ios_base::in | std::ios_base::out | std::ios::binary | std::ios::trunc);
		ASSERT_TRUE(file.is_open());
		ASSERT_TRUE(file);
		ASSERT_FALSE(!file);
	}
	{
		io::file file(service, std::filesystem::path("test.bin"),
					  std::ios_base::in | std::ios_base::out | std::ios::binary | std::ios::trunc);
		ASSERT_TRUE(file.is_open());
		ASSERT_TRUE(file);
		ASSERT_FALSE(!file);
	}
	{
		io::file file(service);
		ASSERT_FALSE(file.is_open());
		ASSERT_FALSE(file);
		ASSERT_TRUE(!file);
	}
	{
		io::file file(service);
		file.open("test.bin", std::ios_base::in | std::ios_base::out | std::ios::binary | std::ios::trunc);
		ASSERT_TRUE(file.is_open());
		ASSERT_TRUE(file);
		ASSERT_FALSE(!file);
	}
	{
		io::file file(service);
		file.open(std::string("test.bin"), std::ios_base::in | std::ios_base::out | std::ios::binary | std::ios::trunc);
		ASSERT_TRUE(file.is_open());
		ASSERT_TRUE(file);
		ASSERT_FALSE(!file);
	}
	{
		io::file file(service);
		file.open(std::filesystem::path("test.bin"),
				  std::ios_base::in | std::ios_base::out | std::ios::binary | std::ios::trunc);
		ASSERT_TRUE(file.is_open());
		ASSERT_TRUE(file);
		ASSERT_FALSE(!file);
	}
	{
		io::file file(service);
		ASSERT_THROW(file.open(""), std::system_error);
		ASSERT_FALSE(file.is_open());
		ASSERT_FALSE(file);
		ASSERT_TRUE(!file);
	}
}

TEST(ASYNCPP_IO, FileWrite) {
	io::io_service service;

	io::file file(service, "test.bin", std::ios_base::in | std::ios_base::out | std::ios::binary | std::ios::trunc);
	ASSERT_TRUE(file);

	size_t write_size;
	async_launch_scope scope;
	scope.invoke([&file, &write_size, &service]() -> task<> {
		write_size = co_await file.write("Hello World", 11, 0);
		service.stop();
	});

	service.run();
	ASSERT_TRUE(scope.all_done());

	ASSERT_EQ(write_size, 11);
	ASSERT_EQ(file.size(), 11);
	auto content = read_file("test.bin");
	ASSERT_EQ(content.size(), 11);
	ASSERT_EQ(content, "Hello World");
}

TEST(ASYNCPP_IO, FileRead) {
	std::ofstream("test.bin", std::ios::out | std::ios::trunc | std::ios::binary) << "Hello World";

	io::io_service service;
	io::file file(service, "test.bin", std::ios_base::in | std::ios::binary);
	ASSERT_TRUE(file);

	size_t read_size;
	std::string read;
	read.resize(file.size());
	async_launch_scope scope;
	scope.invoke([&]() -> task<> {
		read_size = co_await file.read(read.data(), read.size(), 0);
		service.stop();
	});

	service.run();
	ASSERT_TRUE(scope.all_done());

	ASSERT_EQ(read_size, 11);
	ASSERT_EQ(read, "Hello World");

	scope.invoke([&]() -> task<> {
		read_size = co_await file.read(read.data(), read.size(), 6);
		service.stop();
	});
	service.run();
	ASSERT_TRUE(scope.all_done());

	ASSERT_EQ(read_size, 5);
	read.resize(read_size);
	ASSERT_EQ(read, "World");
}

TEST(ASYNCPP_IO, FileOpenClose) {
	io::io_service service;

	io::file file(service, "test.bin", std::ios_base::in | std::ios_base::out | std::ios::binary | std::ios::trunc);
	ASSERT_TRUE(file.is_open());
	ASSERT_TRUE(file);
	ASSERT_FALSE(!file);

	file.close();
	ASSERT_FALSE(file.is_open());
	ASSERT_FALSE(file);
	ASSERT_TRUE(!file);

	file.open("test.bin", std::ios_base::in | std::ios_base::out | std::ios::binary | std::ios::trunc);
	ASSERT_TRUE(file.is_open());
	ASSERT_TRUE(file);
	ASSERT_FALSE(!file);
}
