'use client';

import { useState, useEffect, useCallback } from 'react';
import { safeJsonParse } from '@/lib/utils';

/**
 * Sync state with localStorage
 * Handles SSR safely
 */
export function useLocalStorage<T>(
  key: string,
  initialValue: T
): [T, (value: T | ((prev: T) => T)) => void, () => void] {
  // Initialize state
  const [storedValue, setStoredValue] = useState<T>(() => {
    if (typeof window === 'undefined') {
      return initialValue;
    }
    const item = localStorage.getItem(key);
    return item ? safeJsonParse(item, initialValue) : initialValue;
  });

  // Update localStorage when state changes
  useEffect(() => {
    if (typeof window !== 'undefined') {
      localStorage.setItem(key, JSON.stringify(storedValue));
    }
  }, [key, storedValue]);

  // Setter function
  const setValue = useCallback((value: T | ((prev: T) => T)) => {
    setStoredValue((prev) => {
      const newValue = value instanceof Function ? value(prev) : value;
      return newValue;
    });
  }, []);

  // Remove function
  const removeValue = useCallback(() => {
    setStoredValue(initialValue);
    if (typeof window !== 'undefined') {
      localStorage.removeItem(key);
    }
  }, [key, initialValue]);

  return [storedValue, setValue, removeValue];
}
