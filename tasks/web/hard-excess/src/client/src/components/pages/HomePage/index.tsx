import React, { useContext, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Api from 'src/Api';
import { Context } from 'src/Context';
import LoginForm from 'src/components/forms/LoginForm';
import './index.css';

const HomePage: React.FunctionComponent = () => {
    const context = useContext(Context);
    const navigate = useNavigate();

    useEffect(() => {
        if (typeof context.name !== 'undefined') {
            navigate('/blog');
            return;
        }

        const load = async () => {
            const response = await Api.Profile({ });
    
            if (typeof response.error !== 'undefined') {
                context.setName(undefined);
                return;
            }
    
            context.setName(response.response!.name);
        };

        load();
    }, [context.name]);

    return (
        <div className='HomePage'>
            <div className='HomePage-Header'>
                <span className='HomePage-Title'>Excess | Home</span>
            </div>
            <div className='HomePage-Container'>
                <LoginForm></LoginForm>
            </div>
        </div>
    );
};

export default HomePage;
