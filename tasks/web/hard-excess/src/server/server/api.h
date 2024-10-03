#ifndef _SERVER_API_H
#define _SERVER_API_H

#include <string>
#include <optional>

#include <services/auth.h>
#include <services/blog.h>
#include <services/session.h>

#include <third_party/httplib.h>


namespace Excess::Server {

    class BadRequestError final : public std::runtime_error {
    public:
        BadRequestError(const std::string& error)
            : std::runtime_error(error) { }
    };

    class Api final {
    public:
        Api(Services::Auth& auth, Services::Blog& blog, Services::Session& session);
        ~Api();

        void HandleRegister(const httplib::Request& req, httplib::Response& res);
        void HandleLogin(const httplib::Request& req, httplib::Response& res);
        void HandleLogout(const httplib::Request& req, httplib::Response& res);
        void HandleProfile(const httplib::Request& req, httplib::Response& res);

        void HandleNewMessage(const httplib::Request& req, httplib::Response& res);
        void HandleViewMessage(const httplib::Request& req, httplib::Response& res);
        void HandleSearchMessages(const httplib::Request& req, httplib::Response& res);

        void HandleRenderMessage(const httplib::Request& req, httplib::Response& res);

        void HandleException(const httplib::Request& req, httplib::Response& res, const std::exception_ptr ptr);

    private:
        std::optional<std::string> GetCurrentAuthor(const httplib::Request& req, httplib::Response& res);
        void SetCurrentAuthor(httplib::Response& res, const std::string& name);

        Services::Auth& AuthService;
        Services::Blog& BlogService;
        Services::Session& SessionService;
    };
    
}

#endif /* _SERVER_API_H */
