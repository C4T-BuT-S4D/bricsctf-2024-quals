#include <utils/utils.h>

#include <iomanip>
#include <sstream>
#include <cstring>
#include <sys/random.h>

#include <third_party/sha256.h>

using namespace std::string_literals;

using namespace Excess;
using namespace Excess::Utils;


std::string Utils::MakeSHA256Hash(const std::string& data) {
    SHA256_CTX ctx = { 0 };
    unsigned char buffer[32] = { 0 };

    sha256_init(&ctx);
    sha256_update(&ctx, reinterpret_cast<const BYTE*>(data.c_str()), data.size());
    sha256_final(&ctx, buffer);

    std::stringstream stream;
    stream << std::hex << std::setfill('0');

    for (auto c : buffer) {
        stream << std::setw(2) << static_cast<unsigned>(c);
    }

    return stream.str();
}

std::string Utils::GenerateRandomUUID() {
    unsigned char buffer[16];
    auto result = getrandom(buffer, sizeof(buffer) * sizeof(unsigned char), 0);

    if (result < 0) {
        throw std::runtime_error("failed to generate random id: "s + std::strerror(errno));
    }

    char id[16*2 + 4 + 1];
    auto format = "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x";

    snprintf(
        id, sizeof(id) / sizeof(char), format,
        buffer[0], buffer[1], buffer[2], buffer[3],
        buffer[4], buffer[5], buffer[6], buffer[7],
        buffer[8], buffer[9], buffer[10], buffer[11],
        buffer[12], buffer[13], buffer[14], buffer[15]
    );

    return id;
}
