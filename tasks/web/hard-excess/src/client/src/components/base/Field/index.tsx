import React from 'react';
import './index.css';

type IFieldProps = {
    name: string,
    label?: string,
    placeholder?: string,
    setValue: React.Dispatch<React.SetStateAction<string>>,
};

const Field: React.FunctionComponent<IFieldProps> = (props) => {
    const { name, label, placeholder, setValue } = props;

    const onChangeHandler: React.EventHandler<React.SyntheticEvent<HTMLInputElement>> = (event) => {
        event.preventDefault();

        const target = event.target as HTMLInputElement;

        setValue(target.value);
    };

    return (
        <div className='Field'>
            <label htmlFor={name}>{label}</label>
            <input type='text' name={name} placeholder={placeholder} onChange={onChangeHandler}/>
        </div>
    );
};

export default Field;
