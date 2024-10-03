import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Api from 'src/Api';
import Button from 'src/components/base/Button';
import Error from 'src/components/base/Error';
import Field from 'src/components/base/Field';
import './index.css';

const NewMessageForm: React.FunctionComponent = () => {
    const navigate = useNavigate();

    const [error, setError] = useState<string | undefined>(undefined);

    const [title, setTitle] = useState('');
    const [content, setContent] = useState('');

    const addClickHandler: React.EventHandler<React.SyntheticEvent<HTMLButtonElement>> = async (event) => {
        event.preventDefault();

        const response = await Api.NewMessage({
            title: title,
            content: content,
        });

        if (typeof response.error !== 'undefined') {
            setError(response.error);
            return;
        }

        setError(undefined);
        navigate(`/message/${response.response!.id}`);
    };

    const cancelClickHandler: React.EventHandler<React.SyntheticEvent<HTMLButtonElement>> = async (event) => {
        event.preventDefault();

        navigate('/blog');
    };

    return (
        <div className='NewMessageForm'>
            <Field label='Title: ' name='title' placeholder='my first note' setValue={setTitle}/>
            <Field label='Content: ' name='content' placeholder='hello world' setValue={setContent}/>
            <div className='NewMessageForm-Buttons'>
                <Button onClick={addClickHandler} id='add' text='Add message'/>
                <Button onClick={cancelClickHandler} id='cancel' text='Cancel'/>
            </div>
            <Error error={error}></Error>
        </div>
    );
};

export default NewMessageForm;
