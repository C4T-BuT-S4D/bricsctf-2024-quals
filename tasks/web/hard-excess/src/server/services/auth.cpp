#include <services/auth.h>
#include <utils/utils.h>

using namespace std::string_literals;

using namespace Excess;
using namespace Excess::Services;


std::string MakePasswordHash(const std::string& password) {
    const auto salt = "The Twelve Chairs"s;
    const auto pepper = "The Little Golden Calf"s;

    return Utils::MakeSHA256Hash(salt + password + pepper);
}

Auth::Auth(Storage::IStorage& storage)
    : Storage(storage) { }

Auth::~Auth() { }

Models::Author Auth::Login(const std::string& name, const std::string& password) {
    auto author = Storage.GetAuthorByName(name);

    if (!author.has_value()) {
        throw InvalidCredentialsError("author does not exist"s);
    }

    if (author.value().GetPassword() != MakePasswordHash(password)) {
        throw InvalidCredentialsError("invalid password"s);
    }

    return author.value();
}

Models::Author Auth::Register(const std::string& name, const std::string& password) {
    auto author = Models::Author(name, MakePasswordHash(password));

    Storage.CreateAuthor(author);

    return author;
}
