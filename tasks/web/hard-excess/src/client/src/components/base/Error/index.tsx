import React from 'react';
import './index.css';

type IErrorProps = {
    error: string | undefined,
};

const Error: React.FunctionComponent<IErrorProps> = (props) => {
    const { error } = props;

    if (typeof error === 'undefined') {
        return (
            <></>
        );
    }

    return (
        <div className='Error'>Error: {error}</div>
    );
};

export default Error;
