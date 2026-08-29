import { createContext, useContext, useState, type ReactNode } from "react";
import type { MailShieldEmailContext } from "../api/client";

interface ChatContextType {
  isOpen: boolean;
  setIsOpen: (open: boolean) => void;
  activeContext: MailShieldEmailContext | null;
  setActiveContext: (ctx: MailShieldEmailContext | null) => void;
  openWithPrompt: (prompt: string) => void;
  queuedPrompt: string | null;
  clearQueuedPrompt: () => void;
}

const ChatContext = createContext<ChatContextType | undefined>(undefined);

export function ChatProvider({ children }: { children: ReactNode }) {
  const [isOpen, setIsOpen] = useState(false);
  const [activeContext, setActiveContext] = useState<MailShieldEmailContext | null>(null);
  const [queuedPrompt, setQueuedPrompt] = useState<string | null>(null);

  const openWithPrompt = (prompt: string) => {
    setQueuedPrompt(prompt);
    setIsOpen(true);
  };

  const clearQueuedPrompt = () => {
    setQueuedPrompt(null);
  };

  return (
    <ChatContext.Provider
      value={{
        isOpen,
        setIsOpen,
        activeContext,
        setActiveContext,
        openWithPrompt,
        queuedPrompt,
        clearQueuedPrompt,
      }}
    >
      {children}
    </ChatContext.Provider>
  );
}

export function useChat() {
  const ctx = useContext(ChatContext);
  if (!ctx) {
    throw new Error("useChat must be used within a ChatProvider");
  }
  return ctx;
}
