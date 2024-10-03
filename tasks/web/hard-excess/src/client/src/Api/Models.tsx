export type RegisterRequest = {
    name: string,
    password: string,
};

export type RegisterResponse = {
    error?: string,
    response?: {
        name: string,
    },
};

export type LoginRequest = {
    name: string,
    password: string,
};

export type LoginResponse = {
    error?: string,
    response?: {
        name: string,
    },
};

export type LogoutRequest = { };

export type LogoutResponse = {
    error?: string,
};

export type ProfileRequest = { };

export type ProfileResponse = {
    error?: string,
    response?: {
        name: string,
    },
};

export type NewMessageRequest = {
    title: string,
    content: string,
};

export type NewMessageResponse = {
    error?: string,
    response?: {
        id: string,
    },
};

export type ViewMessageRequest = {
    id: string,
};

export type ViewMessageResponse = {
    error?: string,
    response?: {
        id: string,
        author: string,
        title: string,
        content: string,
    },
};

export type SearchMessagesRequest = {
    content?: string,
};

export type SearchMessagesResponse = {
    error?: string,
    response?: {
        id: string,
        title: string,
    }[],
};

export type RenderMessageRequest = {
    id: string,
};

export type RenderMessageResponse = {
    error?: string,
    response?: string,
};
