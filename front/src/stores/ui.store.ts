import { create } from 'zustand';

interface UIState {
  // Sidebar state
  isSidebarOpen: boolean;
  toggleSidebar: () => void;
  setSidebarOpen: (open: boolean) => void;

  // Modal state
  activeModal: string | null;
  openModal: (modalId: string) => void;
  closeModal: () => void;

  // Theme preference
  theme: 'light' | 'dark' | 'system';
  setTheme: (theme: 'light' | 'dark' | 'system') => void;

  // Loading states
  isPageLoading: boolean;
  setPageLoading: (loading: boolean) => void;
}

/**
 * UI store
 * Manages global UI state like sidebar, modals, and loading states
 */
export const useUIStore = create<UIState>()((set) => ({
  // Sidebar
  isSidebarOpen: true,
  toggleSidebar: () => set((state) => ({ isSidebarOpen: !state.isSidebarOpen })),
  setSidebarOpen: (open) => set({ isSidebarOpen: open }),

  // Modal
  activeModal: null,
  openModal: (modalId) => set({ activeModal: modalId }),
  closeModal: () => set({ activeModal: null }),

  // Theme
  theme: 'system',
  setTheme: (theme) => set({ theme }),

  // Loading
  isPageLoading: false,
  setPageLoading: (loading) => set({ isPageLoading: loading }),
}));
