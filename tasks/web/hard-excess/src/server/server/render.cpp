#include <server/render.h>

#include <map>
#include <sstream>

using namespace Excess;
using namespace Excess::Server;


const std::map<char, std::string> EscapeCharacters = {
    {'<', "&lt;"},
    {'>', "&gt;"},
};

const char MessageTemplate[] = (
    "<div class=\"Message\">"
        "<div class=\"Message-Title\">"
            "<span>%s</span>"
        "</div>"
        "<div class=\"Message-Author\">"
            "<span>%s</span>"
        "</div>"
        "<div class=\"Message-Content\">"
            "<span>%s</span>"
        "</div>"
    "</div>"
);

std::string EscapeHtml(const std::string& str) {
    std::stringstream stream;

    for (auto& symbol : str) {
        if (!EscapeCharacters.contains(symbol)) {
            stream << symbol;
            continue;
        }

        stream << EscapeCharacters.at(symbol);
    }

    return stream.str();
}

std::string Server::RenderMessage(const Models::Message& message) {
    auto title = EscapeHtml(message.GetTitle());
    auto author = EscapeHtml(message.GetAuthor());
    auto content = EscapeHtml(message.GetContent());

    auto size = snprintf(
        nullptr, 0,
        MessageTemplate,
        title.c_str(), author.c_str(), content.c_str()
    );

    auto buffer = reinterpret_cast<char*>(alloca(size + 1));

    snprintf(
        buffer, size + 1,
        MessageTemplate,
        title.c_str(), author.c_str(), content.c_str()
    );

    return std::string(buffer);
}
