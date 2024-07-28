#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>
#include <stdexcept>

#include "common.h"
#include "dropper.h"

extern unsigned char LibJava[];
extern const size_t LibJavaLength;

extern unsigned char LibVerify[];
extern const size_t LibVerifyLength;

extern unsigned char LibJimage[];
extern const size_t LibJimageLength;

extern unsigned char LibNet[];
extern const size_t LibNetLength;

extern unsigned char LibNio[];
extern const size_t LibNioLength;

extern unsigned char LibZip[];
extern const size_t LibZipLength;

extern unsigned char Modules[];
extern const size_t ModulesLength;

extern unsigned char LibJvm[];
extern const size_t LibJvmLength;

void WriteDataToFile(std::experimental::filesystem::path path, unsigned char *data, size_t length) {
    DecryptData(data, length);

    const size_t chunkSize = 0x10000;

    auto file = std::fopen(path.c_str(), "wb");

    /*
    for (size_t i = 0; i < length; i += chunkSize) {
        size_t copySize = chunkSize;

        if (i + chunkSize > length) {
            copySize = length - i;
        }

        auto size = std::fwrite(data + i, sizeof(unsigned char), copySize, file);

        if (size < copySize) {
            std::fclose(file);

            throw std::runtime_error("failed to write data");
        }
    }
    */

    std::fwrite(data, sizeof(unsigned char), length, file);

    std::fclose(file);

    return;
}

Dropper::Dropper() {
    char suffix[20] = "dolly-XXXXXX";

    RuntimeDirectory = std::experimental::filesystem::temp_directory_path() / mktemp(suffix);
    std::experimental::filesystem::create_directory(RuntimeDirectory);

    return;
}

Dropper::~Dropper() {
    std::experimental::filesystem::remove_all(RuntimeDirectory);

    return;
}

void Dropper::Drop() {
    auto libPath = RuntimeDirectory / "lib";
    auto serverPath = RuntimeDirectory / "lib" / "server";

    std::experimental::filesystem::create_directories(libPath);
    std::experimental::filesystem::create_directories(serverPath);

    WriteDataToFile(libPath / "libjava.so", LibJava, LibJavaLength);
    WriteDataToFile(libPath / "libverify.so", LibVerify, LibVerifyLength);
    WriteDataToFile(libPath / "libjimage.so", LibJimage, LibJimageLength);
    WriteDataToFile(libPath / "libnet.so", LibNet, LibNetLength);
    WriteDataToFile(libPath / "libnio.so", LibNio, LibNioLength);
    WriteDataToFile(libPath / "libzip.so", LibZip, LibZipLength);
    WriteDataToFile(libPath / "modules", Modules, ModulesLength);

    WriteDataToFile(serverPath / "libjvm.so", LibJvm, LibJvmLength);

    /*
    Threads.emplace_back(
        [libPath, serverPath]() -> void {
            WriteDataToFile(libPath / "libjava.so", LibJava, LibJavaLength);
        }
    );
    Threads.emplace_back(
        [libPath, serverPath]() -> void {
            WriteDataToFile(libPath / "libverify.so", LibVerify, LibVerifyLength);
        }
    );
    Threads.emplace_back(
        [libPath, serverPath]() -> void {
            WriteDataToFile(libPath / "libjimage.so", LibJimage, LibJimageLength);
        }
    );
    Threads.emplace_back(
        [libPath, serverPath]() -> void {
            WriteDataToFile(libPath / "libnet.so", LibNet, LibNetLength);
        }
    );
    Threads.emplace_back(
        [libPath, serverPath]() -> void {
            WriteDataToFile(libPath / "libnio.so", LibNio, LibNioLength);
        }
    );
    Threads.emplace_back(
        [libPath, serverPath]() -> void {
            WriteDataToFile(libPath / "libzip.so", LibZip, LibZipLength);
        }
    );
    Threads.emplace_back(
        [libPath, serverPath]() -> void {
            WriteDataToFile(libPath / "modules", Modules, ModulesLength);
        }
    );

    Threads.emplace_back(
        [libPath, serverPath]() -> void {
            WriteDataToFile(serverPath / "libjvm.so", LibJvm, LibJvmLength);
        }
    );
    */

    return;
}

std::experimental::filesystem::path Dropper::GetRuntimePath() {
    return RuntimeDirectory;
}

void Dropper::Wait() {
    /*
    if (Threads.size() == 0) {
        return;
    }

    for (auto& thread : Threads) {
        thread.join();
    }

    Threads.clear();
    */

    return;
}
