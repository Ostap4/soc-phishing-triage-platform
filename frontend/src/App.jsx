import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";

import AuthPage from "./routes/login";
import Dashboard from "./routes/index";
import ResetPassword from "./pages/ResetPassword";


function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<AuthPage />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/reset-password" element={<ResetPassword />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;