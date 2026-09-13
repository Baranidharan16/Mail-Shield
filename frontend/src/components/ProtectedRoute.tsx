import React from "react";
import { Navigate, useLocation, Outlet } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { Shield, Loader2 } from "lucide-react";

interface ProtectedRouteProps {
  children?: React.ReactNode;
}

export default function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-lab-950 text-lab-100">
        <div className="flex flex-col items-center gap-4 p-8 rounded-2xl glass-card border border-white/10 glow-green">
          <div className="relative flex items-center justify-center w-12 h-12 rounded-xl bg-phosphor-500/15 border border-phosphor-500/35">
            <Shield className="w-6 h-6 text-phosphor-400 animate-pulse" />
          </div>
          <div className="flex items-center gap-2 text-sm font-mono text-phosphor-300">
            <Loader2 className="w-4 h-4 animate-spin text-phosphor-400" />
            <span>VERIFYING CREDENTIALS...</span>
          </div>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children ? <>{children}</> : <Outlet />;
}
