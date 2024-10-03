#ifndef _MODELS_AUTHOR_H
#define _MODELS_AUTHOR_H

#include <string>


namespace Excess::Models {

    class Author final {
    public:
        Author(const std::string& name, const std::string& password);

        const std::string& GetName() const;
        const std::string& GetPassword() const;

    private:
        const std::string Name;
        const std::string Password;
    };

}

#endif /* _MODELS_AUTHOR_H */
