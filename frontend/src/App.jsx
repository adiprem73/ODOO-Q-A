
import React, { useState, createContext, useContext } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import NavBar from "./components/NavBar";
import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage";
import SignupPage from "./pages/SignupPage";
import AskQuestion from "./pages/AskQuestion";
import QuestionDetail from "./pages/QuestionDetail";
import AdminDashboard from "./pages/AdminDashboard";
import ProfilePage from "./pages/ProfilePage";
import GuestUserPage from "./pages/GuestUserPage";
import Home from "./pages/Home";
import "./App.css";


// Auth Context
const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

function App() {
  const [user, setUser] = useState(null);

  const login = (userData) => {
    setUser(userData);
  };

  const logout = () => {
    setUser(null);
  };

  const authValue = {
    user,
    login,
    logout,
    isAuthenticated: !!user,
    isAdmin: user?.role === "admin",
  };

  return (
    
    <AuthContext.Provider value={authValue}>
      <Router>

        <div className="min-h-screen bg-gradient-to-br from-purple-50 via-blue-50 to-indigo-100">
          <NavBar />
          <main className="pt-20">
            <AnimatePresence mode="wait">
              <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/forum" element={<LandingPage />} />
                <Route path="/login" element={<LoginPage />} />
                <Route path="/signup" element={<SignupPage />} />
                <Route
                  path="/ask"
                  element={
                    authValue.isAuthenticated ? (
                      <AskQuestion />
                    ) : (
                      <Navigate to="/login" />
                    )
                  }
                />
                <Route path="/questions/:id" element={<QuestionDetail />} />
                <Route
                  path="/admin"
                  element={
                    authValue.isAdmin ? <AdminDashboard /> : <Navigate to="/" />
                  }
                />
                <Route
                  path="/profile"
                  element={
                    authValue.isAuthenticated ? (
                      <ProfilePage />
                    ) : (
                      <GuestUserPage />
                    )
                  }
                />
              </Routes>
            </AnimatePresence>
          </main>
        </div>
      </Router>
    </AuthContext.Provider>
  
  );
}

export default App;
