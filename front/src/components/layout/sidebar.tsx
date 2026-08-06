'use client';

import Link from 'next/link';
import { Route } from 'next';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import { useUIStore } from '@/stores';

interface SidebarItem {
  label: string;
  href: Route;
  icon?: React.ReactNode;
}

interface SidebarProps {
  items: SidebarItem[];
  className?: string;
}

export function Sidebar({ items, className }: SidebarProps) {
  const pathname = usePathname();
  const { isSidebarOpen } = useUIStore();

  return (
    <aside
      className={cn(
        'fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r bg-background transition-transform duration-300 lg:static lg:translate-x-0',
        !isSidebarOpen && '-translate-x-full',
        className
      )}
    >
      <div className="flex h-16 items-center border-b px-6">
        <Link href="/" className="text-xl font-bold">
          Minisource
        </Link>
      </div>
      <nav className="flex-1 space-y-1 p-4">
        {items.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-primary text-primary-foreground'
                  : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
              )}
            >
              {item.icon}
              {item.label}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
