import { Box } from '@mui/material'
import React from 'react'
import {  Route, Routes } from 'react-router-dom'
import App from './App'
import Copyright from './components/Copyright';
import Login from './pages/Login';
import SignUp from './pages/SignUp';





const AppRouter = () => {
  return (
    <>
        <Routes>
            <Route path="/"  element={<App /> }   />
            <Route path="/login"  element={<Login /> }   />
            <Route path="/signup"  element={<SignUp /> }   />

        </Routes>
                    
        <Box mt={5}>
              <Copyright />
        </Box>
    </>
  )
}

export default AppRouter