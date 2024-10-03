import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import Api from 'src/Api';
import Button from 'src/components/base/Button';
import Error from 'src/components/base/Error';
import './index.css';

const ViewMessagePage: React.FunctionComponent = () => {
    const { id } = useParams();

    const navigate = useNavigate();

    const [html, setHtml] = useState('');
    const [error, setError] = useState<string | undefined>(undefined);

    useEffect(() => {
        loadMessage();
    }, []);

    if (typeof id === 'undefined') {
        navigate('/blog');
        return <></>;
    }

    const loadMessage = async () => {
        const response = await Api.RenderMessage({ id });

        if (typeof response.error !== 'undefined') {
            setError(response.error);
            return;
        }

        setError(undefined);
        setHtml(response.response!);
    };

    const backClickHandler: React.EventHandler<React.SyntheticEvent<HTMLButtonElement>> = async (event) => {
        event.preventDefault();

        navigate('/blog');
    };

    return (
        <div className='ViewMessagePage'>
            <div className='ViewMessagePage-Header'>
                <span className='ViewMessagePage-Title'>Excess | Message</span>
            </div>
            <div className='ViewMessagePage-Container'>
                <Error error={error}/>
                <div className='ViewMessagePage-Message' dangerouslySetInnerHTML={{__html: html}}></div>
                <div className='ViewMessagePage-Buttons'>
                    <Button onClick={backClickHandler} id='back' text='Back'/>
                </div>
            </div>
        </div>
    );
};

export default ViewMessagePage;
