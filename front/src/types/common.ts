/**
 * Common type definitions
 */

/**
 * Generic API response type
 */
export type ApiResponse<T> = {
  data: T;
  message?: string;
  success: boolean;
};

/**
 * Paginated response
 */
export interface PaginatedResponse<T> {
  data: T[];
  meta: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

/**
 * Pagination params
 */
export interface PaginationParams {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

/**
 * Generic async function type
 */
export type AsyncFn<T = void> = () => Promise<T>;

/**
 * Make specific keys required
 */
export type RequireFields<T, K extends keyof T> = T & Required<Pick<T, K>>;

/**
 * Make all keys optional except specified ones
 */
export type PartialExcept<T, K extends keyof T> = Partial<Omit<T, K>> & Pick<T, K>;

/**
 * Common status types
 */
export type Status = 'idle' | 'loading' | 'success' | 'error';

/**
 * Base entity with common fields
 */
export interface BaseEntity {
  id: string;
  createdAt: string;
  updatedAt: string;
}
