#include <models/author.h>

using namespace Excess::Models;


Author::Author(const std::string& name, const std::string& password)
    : Name(name)
    , Password(password) { }

const std::string& Author::GetName() const {
    return Name;
}

const std::string& Author::GetPassword() const {
    return Password;
}
