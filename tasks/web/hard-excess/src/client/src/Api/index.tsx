import {
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginResponse,
    LogoutRequest, LogoutResponse,
    ProfileRequest, ProfileResponse,
    NewMessageRequest, NewMessageResponse,
    ViewMessageRequest, ViewMessageResponse,
    SearchMessagesRequest, SearchMessagesResponse,
    RenderMessageRequest, RenderMessageResponse,
} from 'src/Api/Models';

const HandleError = async (err: Error): Promise<Record<string, any>> => {
    return { error: err.message };
};

export const Register = async (req: RegisterRequest): Promise<RegisterResponse> => {
    const url = `/api/register`;
    const response = await fetch(url, {
        mode: 'cors',
        credentials: 'same-origin',
        method: 'POST',
        body: `name=${req.name}&password=${req.password}`,
    }).then(r => r.json()).catch(HandleError) as Record<string, any>;

    if (typeof response.error !== 'undefined') {
        return {
            error: response.error,
        };
    }

    return {
        response: {
            name: response.response.name,
        },
    };
};

export const Login = async (req: LoginRequest): Promise<LoginResponse> => {
    const url = `/api/login`;
    const response = await fetch(url, {
        mode: 'cors',
        credentials: 'same-origin',
        method: 'POST',
        body: `name=${req.name}&password=${req.password}`,
    }).then(r => r.json()).catch(HandleError) as Record<string, any>;

    if (typeof response.error !== 'undefined') {
        return {
            error: response.error,
        };
    }

    return {
        response: {
            name: response.response.name,
        },
    };
};

export const Logout = async (req: LogoutRequest): Promise<LogoutResponse> => {
    const url = `/api/logout`;
    const response = await fetch(url, {
        mode: 'cors',
        credentials: 'same-origin',
        method: 'POST',
    }).then(r => r.json()).catch(HandleError) as Record<string, any>;

    if (typeof response.error !== 'undefined') {
        return {
            error: response.error,
        };
    }

    return { };
};

export const Profile = async (req: ProfileRequest): Promise<ProfileResponse> => {
    const url = `/api/profile`;
    const response = await fetch(url, {
        mode: 'cors',
        credentials: 'same-origin',
    }).then(r => r.json()).catch(HandleError) as Record<string, any>;

    if (typeof response.error !== 'undefined') {
        return {
            error: response.error,
        };
    }

    return {
        response: {
            name: response.response.name,
        },
    };
};

export const NewMessage = async (req: NewMessageRequest): Promise<NewMessageResponse> => {
    const url = `/api/message`;
    const response = await fetch(url, {
        mode: 'cors',
        credentials: 'same-origin',
        method: 'POST',
        body: `title=${req.title}&content=${req.content}`,
    }).then(r => r.json()).catch(HandleError) as Record<string, any>;

    if (typeof response.error !== 'undefined') {
        return {
            error: response.error,
        };
    }

    return {
        response: {
            id: response.response.id,
        },
    };
};

export const ViewMessage = async (req: ViewMessageRequest): Promise<ViewMessageResponse> => {
    const url = `/api/message/${req.id}`;
    const response = await fetch(url, {
        mode: 'cors',
    }).then(r => r.json()).catch(HandleError) as Record<string, any>;

    if (typeof response.error !== 'undefined') {
        return {
            error: response.error,
        };
    }

    return {
        response: {
            id: response.response.id,
            author: response.response.author,
            title: response.response.title,
            content: response.response.content,
        },
    };
};

export const SearchMessages = async (req: SearchMessagesRequest): Promise<SearchMessagesResponse> => {
    const url = (
        typeof req.content !== 'undefined' && req.content.length > 0
        ? `/api/messages?content=${encodeURIComponent(req.content)}`
        : `/api/messages`
    );

    const response = await fetch(url, {
        mode: 'cors',
        credentials: 'same-origin',
    }).then(r => r.json()).catch(HandleError) as Record<string, any>;

    if (typeof response.error !== 'undefined') {
        return {
            error: response.error,
        };
    }

    const messages: {
        id: string,
        title: string,
    }[] = [];

    if (typeof response.response !== 'undefined') {
        response.response.forEach((message: any) => messages.push({
            id: message.id,
            title: message.title,
        }));
    }

    return {
        response: messages,
    };
};

export const RenderMessage = async (req: RenderMessageRequest): Promise<RenderMessageResponse> => {
    const url = `/api/render/${req.id}`;
    const response = await fetch(url, {
        mode: 'cors',
    }).then(r => r.text());

    try {
        const json = JSON.parse(response);

        return {
            error: json.error,
        };
    } catch(_) {
        return {
            response: response,
        };
    }
};

export default {
    Register,
    Login,
    Logout,
    Profile,
    NewMessage,
    ViewMessage,
    SearchMessages,
    RenderMessage,
};
