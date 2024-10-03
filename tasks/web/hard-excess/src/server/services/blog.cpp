#include <services/blog.h>
#include <utils/utils.h>

using namespace std::string_literals;

using namespace Excess;
using namespace Excess::Services;


Blog::Blog(Storage::IStorage& storage)
    : Storage(storage) { }

Blog::~Blog() { }

Models::Message Blog::CreateMessage(
    const std::string& author,
    const std::string& title,
    const std::string& content
) {
    auto id = Utils::GenerateRandomUUID();
    auto message = Models::Message(id, author, title, content);

    Storage.CreateMessage(message);

    return message;
}

Models::Message Blog::GetMessage(const std::string& id) {
    auto message = Storage.GetMessageById(id);

    if (!message.has_value()) {
        throw MessageNotFoundError("message "s + id + " does not exist"s);
    }

    return message.value();
}

std::vector<Models::Message> Blog::GetAllMessages(const std::string& author) {
    return Storage.FindMessagesByAuthor(author);
}
