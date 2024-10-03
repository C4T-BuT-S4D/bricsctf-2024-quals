import React, { useContext, useState } from 'react';
import Api from 'src/Api';
import { Context } from 'src/Context';
import Button from 'src/components/base/Button';
import Error from 'src/components/base/Error';
import Field from 'src/components/base/Field';
import './index.css';

const LoginForm: React.FunctionComponent = () => {
    const [error, setError] = useState<string | undefined>(undefined);

    const [name, setName] = useState('');
    const [password, setPassword] = useState('');

    const context = useContext(Context);

    const loginClickHandler: React.EventHandler<React.SyntheticEvent<HTMLButtonElement>> = async (event) => {
        event.preventDefault();

        const response = await Api.Login({
            name: name,
            password: password,
        });

        if (typeof response.error !== 'undefined') {
            setError(response.error);
            return;
        }

        setError(undefined);
        context.setName(response.response!.name);
    };

    const registerClickHandler: React.EventHandler<React.SyntheticEvent<HTMLButtonElement>> = async (event) => {
        event.preventDefault();

        const response = await Api.Register({
            name: name,
            password: password,
        });

        if (typeof response.error !== 'undefined') {
            setError(response.error);
            return;
        }

        context.setName(response.response!.name);
    };

    return (
        <div className='LoginForm'>
            <Field label='Name: ' name='name' placeholder='author' setValue={setName}/>
            <Field label='Password: ' name='password' placeholder='qwerty123' setValue={setPassword}/>
            <div className='LoginForm-Buttons'>
                <Button onClick={loginClickHandler} id='login' text='Login'/>
                <Button onClick={registerClickHandler} id='register' text='Register'/>
            </div>
            <Error error={error}></Error>
        </div>
    );
};

export default LoginForm;
