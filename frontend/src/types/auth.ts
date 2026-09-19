export interface UserProfile {
  id: string;
  name: string;
  email: string;
  is_active: boolean;
  created_at: string | null;
  updated_at?: string | null;
  last_login: string | null;
  total_investigations: number;
  threats_detected: number;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  user: UserProfile;
}

export interface AuthStatusResponse {
  authenticated: boolean;
  user: UserProfile | null;
}
