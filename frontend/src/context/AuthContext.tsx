import React, { createContext, useContext, useState, useEffect } from "react";
import type { UserProfile } from "../types/auth";
import {
  loginUser as apiLogin,
  registerUser as apiRegister,
  logoutUser as apiLogout,
  getCurrentUser as apiGetCurrentUser,
} from "../api/client";

interface AuthContextType {
  user: UserProfile | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (name: string, email: string, password: string, confirm_password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(() => {
    try {
      const cached = localStorage.getItem("mailshield_user");
      return cached ? JSON.parse(cached) : null;
    } catch {
      return null;
    }
  });

  const [token, setToken] = useState<string | null>(() => {
    try {
      return localStorage.getItem("mailshield_token");
    } catch {
      return null;
    }
  });

  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Validate session on mount
  useEffect(() => {
    let mounted = true;
    async function restoreSession() {
      const storedToken = localStorage.getItem("mailshield_token");
      if (!storedToken) {
        if (mounted) setIsLoading(false);
        return;
      }

      try {
        const profile = await apiGetCurrentUser();
        if (mounted) {
          setUser(profile);
          localStorage.setItem("mailshield_user", JSON.stringify(profile));
        }
      } catch (err) {
        console.warn("Session expired or invalid, logging out.");
        if (mounted) {
          setUser(null);
          setToken(null);
          localStorage.removeItem("mailshield_token");
          localStorage.removeItem("mailshield_user");
        }
      } finally {
        if (mounted) setIsLoading(false);
      }
    }

    restoreSession();
    return () => {
      mounted = false;
    };
  }, []);

  async function login(email: string, password: string) {
    setIsLoading(true);
    try {
      const res = await apiLogin({ email, password });
      setToken(res.access_token);
      setUser(res.user);
      localStorage.setItem("mailshield_token", res.access_token);
      localStorage.setItem("mailshield_user", JSON.stringify(res.user));
    } finally {
      setIsLoading(false);
    }
  }

  async function register(name: string, email: string, password: string, confirm_password: string) {
    setIsLoading(true);
    try {
      const res = await apiRegister({ name, email, password, confirm_password });
      setToken(res.access_token);
      setUser(res.user);
      localStorage.setItem("mailshield_token", res.access_token);
      localStorage.setItem("mailshield_user", JSON.stringify(res.user));
    } finally {
      setIsLoading(false);
    }
  }

  async function logout() {
    try {
      await apiLogout().catch(() => {});
    } finally {
      setUser(null);
      setToken(null);
      localStorage.removeItem("mailshield_token");
      localStorage.removeItem("mailshield_user");
    }
  }

  async function refreshUser() {
    try {
      const profile = await apiGetCurrentUser();
      setUser(profile);
      localStorage.setItem("mailshield_user", JSON.stringify(profile));
    } catch {
      // silent
    }
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user && !!token,
        isLoading,
        login,
        register,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
