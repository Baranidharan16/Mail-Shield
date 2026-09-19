import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import type { UserProfile } from "../types/auth";
import {
  loginUser as apiLogin,
  registerUser as apiRegister,
  logoutUser as apiLogout,
  getCurrentUser as apiGetCurrentUser,
  refreshSession,
  setAccessToken,
  getAccessToken,
  SESSION_EXPIRED_EVENT,
} from "../api/client";

interface AuthContextType {
  user: UserProfile | null;
  token: string | null;
  isAuthenticated: boolean;
  /** true only while the initial session check runs on page load */
  isLoading: boolean;
  /** set when the user was signed out because the session expired */
  sessionExpired: boolean;
  login: (email: string, password: string, rememberMe?: boolean) => Promise<void>;
  register: (name: string, email: string, password: string, confirm_password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [sessionExpired, setSessionExpired] = useState(false);

  const clearSession = useCallback(() => {
    setAccessToken(null);
    setUser(null);
    setToken(null);
  }, []);

  // On page load / new tab: restore the session from the httpOnly refresh cookie.
  useEffect(() => {
    let mounted = true;
    refreshSession()
      .then((res) => {
        if (!mounted) return;
        setToken(res.access_token);
        setUser(res.user);
      })
      .catch(() => {
        if (mounted) clearSession(); // no/expired session, or server unreachable
      })
      .finally(() => {
        if (mounted) setIsLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, [clearSession]);

  // An API call got 401 and the refresh cookie was also rejected.
  useEffect(() => {
    const onExpired = () => {
      clearSession();
      setSessionExpired(true);
    };
    window.addEventListener(SESSION_EXPIRED_EVENT, onExpired);
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, onExpired);
  }, [clearSession]);

  // Keep React state in sync when the API layer silently refreshes the token.
  useEffect(() => {
    const t = setInterval(() => {
      const current = getAccessToken();
      if (current !== token && current) setToken(current);
    }, 5000);
    return () => clearInterval(t);
  }, [token]);

  async function login(email: string, password: string, rememberMe = false) {
    const res = await apiLogin({ email, password, remember_me: rememberMe });
    setSessionExpired(false);
    setToken(res.access_token);
    setUser(res.user);
  }

  async function register(name: string, email: string, password: string, confirm_password: string) {
    const res = await apiRegister({ name, email, password, confirm_password });
    setSessionExpired(false);
    setToken(res.access_token);
    setUser(res.user);
  }

  async function logout() {
    try {
      await apiLogout();
    } catch {
      /* server unreachable — still clear local state */
    } finally {
      clearSession();
      setSessionExpired(false);
    }
  }

  async function refreshUser() {
    try {
      setUser(await apiGetCurrentUser());
    } catch {
      /* handled by the 401 interceptor */
    }
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user && !!token,
        isLoading,
        sessionExpired,
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
