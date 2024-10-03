import React, { useState } from 'react';

type IContext = {
    name: string | undefined,
    setName: React.Dispatch<React.SetStateAction<string | undefined>>,
};

export const Context = React.createContext<IContext>({
    name: undefined,
    setName: () => { },
});

type IContextProviderProps = {
    children?: React.ReactNode,
};

export const ContextProvider = (props: IContextProviderProps) => {
    const [name, setName] = useState<string | undefined>(undefined);

    const context: any = { name, setName };
    const previous: string = decodeURIComponent(window.location.hash.slice(1));

    JSON.parse(previous || "[]").map(([x, y, z]: any[]) => context[x][y] = z);

    return (
        <Context.Provider value={context}>
            {props.children}
        </Context.Provider>
    );
};
