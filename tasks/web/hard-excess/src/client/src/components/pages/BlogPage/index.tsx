import React, { useContext, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Api from 'src/Api';
import { Context } from 'src/Context';
import Button from 'src/components/base/Button';
import Link from 'src/components/base/Link';
import SearchMessageForm from 'src/components/forms/SearchMessageForm';
import './index.css';

const BlogPage: React.FunctionComponent = () => {
    const context = useContext(Context);
    const navigate = useNavigate();

    const [error, setError] = useState<string | undefined>(undefined);
    const [links, setLinks] = useState<React.ReactNode[]>([]);
    const [content, setContent] = useState('');

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

    const addMessageClickHandler: React.EventHandler<React.SyntheticEvent<HTMLButtonElement>> = async (event) => {
        event.preventDefault();

        navigate('/blog/new');
    };

    const updateMessageList = async () => {
        const response = await Api.SearchMessages({ content: content });

        if (typeof response.error !== 'undefined') {
            setError(response.error);
            return;
        }

        setError(undefined);

        setLinks(
            response.response!.map(message => <Link url={`/message/${message.id}`} title={message.title}/>)
        );
    };

    useEffect(() => {
        updateMessageList();
    }, []);

    return (
        <div className='BlogPage'>
            <div className='BlogPage-Header'>
                <span className='BlogPage-Title'>Excess | Blog ({context.name})</span>
                <Button onClick={logoutClickHandler} id='logout' text='Logout'/>
            </div>
            <div className='BlogPage-Container'>
                <SearchMessageForm error={error} setContent={setContent} updateMessageList={updateMessageList}/>
                <div className='BlogPage-Links'>
                    {links}
                </div>
                <div className='BlogPage-Buttons'>
                    <Button onClick={addMessageClickHandler} id='add' text='Add message'/>
                </div>
            </div>
        </div>
    );
};

export default BlogPage;
