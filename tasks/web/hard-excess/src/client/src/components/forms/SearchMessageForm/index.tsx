import React from 'react';
import Button from 'src/components/base/Button';
import Error from 'src/components/base/Error';
import Field from 'src/components/base/Field';
import './index.css';

type ISearchMessageFormProps = {
    error: string | undefined,
    setContent: React.Dispatch<React.SetStateAction<string>>,
    updateMessageList: () => { },
};

const SearchMessageForm: React.FunctionComponent<ISearchMessageFormProps> = (props) => {
    const { error, setContent, updateMessageList } = props;

    const searchClickHandler: React.EventHandler<React.SyntheticEvent<HTMLButtonElement>> = async (event) => {
        event.preventDefault();

        updateMessageList();
    };

    return (
        <div className='SearchMessageForm'>
            <Field label='Filter: ' name='content' setValue={setContent}/>
            <div className='SearchMessageForm-Buttons'>
                <Button onClick={searchClickHandler} id='search' text='Search'/>
            </div>
            <Error error={error}></Error>
        </div>
    );
};

export default SearchMessageForm;
