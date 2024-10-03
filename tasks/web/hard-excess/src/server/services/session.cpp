#include <services/session.h>
#include <utils/utils.h>

#include <fstream>
#include <sstream>

using namespace std::string_literals;

using namespace Excess;
using namespace Excess::Services;


std::string ReadKey(const std::string& keyfile) {
    std::string key;

    std::ifstream file(keyfile);
    std::stringstream stream;

    stream << file.rdbuf();

    return stream.str();
}

std::string CalculateHMAC(const std::string& key, const std::string& data) {
    auto reversed = std::string(key.rbegin(), key.rend());

    return Utils::MakeSHA256Hash(key + Utils::MakeSHA256Hash(reversed + data));
}

Session::Session(const std::string& keyfile)
    : Key(ReadKey(keyfile)) { }

Session::~Session() { }

std::string Session::Serialize(const std::string& data) {
    return data + ":"s + CalculateHMAC(Key, data);
}

std::string Session::Deserialize(const std::string& session) {
    auto index = session.rfind(':');

    if (index == std::string::npos || index == 0 || index == session.size() - 1) {
        throw InvalidSessionError("invalid session format"s);
    }

    auto data = session.substr(0, index);
    auto hmac = session.substr(index + 1);

    if (hmac != CalculateHMAC(Key, const_cast<const std::string&>(data))) {
        throw InvalidSessionError("invalid hmac"s);
    }

    return data;
}
