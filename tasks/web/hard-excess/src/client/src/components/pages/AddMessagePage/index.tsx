import React, { useContext, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Api from 'src/Api';
import { Context } from 'src/Context';
import Button from 'src/components/base/Button';
import NewMessageForm from 'src/components/forms/NewMessageForm';
import './index.css';

const AddMessagePage: React.FunctionComponent = () => {
    const context = useContext(Context);
    const navigate = useNavigate();

    useEffect(() => {
        if (typeof context.name === 'undefined') {
            navigate('/');
        }
    }, [context.name]);

    const logoutClickHandler: React.EventHandler<React.SyntheticEvent<HTMLButtonElement>> = async (event) => {
        event.preventDefault();

        await Api.Logout({ });
        context.setName(undefined);
    };

    return (
        <div className='AddMessagePage'>
            <div className='AddMessagePage-Header'>
                <span className='AddMessagePage-Title'>Excess | New message ({context.name})</span>
                <Button onClick={logoutClickHandler} id='logout' text='Logout'/>
            </div>
            <div className='AddMessagePage-Container'>
                <NewMessageForm/>
            </div>
        </div>
    );
};

export default AddMessagePage;
