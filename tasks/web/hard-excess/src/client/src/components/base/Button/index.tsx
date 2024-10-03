import React from 'react';
import './index.css';

type IButtonProps = {
    id: string,
    text: string,
    onClick: React.EventHandler<React.SyntheticEvent<HTMLButtonElement>>,
};

const Button: React.FunctionComponent<IButtonProps> = (props) => {
    const { id, text, onClick } = props;

    return (
        <div className='Button'>
            <button onClick={onClick} id={id}>{text}</button>
        </div>
    );
};

export default Button;
