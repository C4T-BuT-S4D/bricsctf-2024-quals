#include <models/message.h>

using namespace Excess::Models;


Message::Message(
    const std::string& id,
    const std::string& author,
    const std::string& title,
    const std::string& content
)
    : Id(id)
    , Author(author)
    , Title(title)
    , Content(content) { }

const std::string& Message::GetId() const {
    return Id;
}

const std::string& Message::GetAuthor() const {
    return Author;
}

const std::string& Message::GetTitle() const {
    return Title;
}

const std::string& Message::GetContent() const {
    return Content;
}
