#ifndef _SERVER_RENDER_H
#define _SERVER_RENDER_H

#include <string>

#include <models/message.h>


namespace Excess::Server {

    std::string RenderMessage(const Models::Message& message);

}

#endif /* _SERVER_RENDER_H */
