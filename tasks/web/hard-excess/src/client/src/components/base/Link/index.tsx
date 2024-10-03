import React from 'react';
import './index.css';

type ILinkProps = {
    url: string,
    title: string,
};

const Link: React.FunctionComponent<ILinkProps> = (props) => {
    const { url, title } = props;

    return (
        <div className='Link'>
            <a href={url}>{title}</a>
        </div>
    );
};

export default Link;
