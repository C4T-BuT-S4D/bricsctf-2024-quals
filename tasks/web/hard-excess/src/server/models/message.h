#ifndef _MODELS_MESSAGE_H
#define _MODELS_MESSAGE_H

#include <string>


namespace Excess::Models {

    class Message final {
    public:
        Message(
            const std::string& id,
            const std::string& author,
            const std::string& title,
            const std::string& content
        );

        const std::string& GetId() const;
        const std::string& GetAuthor() const;
        const std::string& GetTitle() const;
        const std::string& GetContent() const;

    private:
        const std::string Id;
        const std::string Author;
        const std::string Title;
        const std::string Content;
    };

}

#endif /* _MODELS_MESSAGE_H */
