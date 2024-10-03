import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { ContextProvider } from 'src/Context';
import HomePage from 'src/components/pages/HomePage';
import BlogPage from 'src/components/pages/BlogPage';
import AddMessagePage from 'src/components/pages/AddMessagePage';
import ViewMessagePage from 'src/components/pages/ViewMessagePage';

const App: React.FunctionComponent = () => {
    return (
        <ContextProvider>
            <Routes>
                <Route path='/' Component={HomePage}></Route>
                <Route path='/blog' Component={BlogPage}></Route>
                <Route path='/blog/new' Component={AddMessagePage}></Route>
                <Route path='/message/:id' Component={ViewMessagePage}></Route>
                <Route path='*' element={<Navigate to='/'/>}></Route>
            </Routes>
        </ContextProvider>
    );
};

export default App;
