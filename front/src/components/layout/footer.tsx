import Link from 'next/link';
import { Route } from 'next';
import { cn } from '@/lib/utils';
import { Separator } from '@minisource/ui';

interface FooterProps {
  className?: string;
}

const footerLinks = {
  product: [
    { label: 'Features', href: '/features' as Route },
    { label: 'Pricing', href: '/pricing' as Route },
    { label: 'Documentation', href: '/docs' as Route },
  ],
  company: [
    { label: 'About', href: '/about' as Route },
    { label: 'Blog', href: '/blog' as Route },
    { label: 'Careers', href: '/careers' as Route },
  ],
  legal: [
    { label: 'Privacy', href: '/privacy' as Route },
    { label: 'Terms', href: '/terms' as Route },
  ],
};

export function Footer({ className }: FooterProps) {
  return (
    <footer className={cn('border-t bg-background', className)}>
      <div className="container py-12">
        <div className="grid grid-cols-2 gap-8 md:grid-cols-4">
          <div className="col-span-2 md:col-span-1">
            <Link href="/" className="text-xl font-bold">
              Minisource
            </Link>
            <p className="mt-4 text-sm text-muted-foreground">
              A modern frontend template for building scalable web applications.
            </p>
          </div>
          <div>
            <h3 className="mb-4 text-sm font-semibold">Product</h3>
            <ul className="space-y-2">
              {footerLinks.product.map((link) => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-sm text-muted-foreground hover:text-foreground"
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="mb-4 text-sm font-semibold">Company</h3>
            <ul className="space-y-2">
              {footerLinks.company.map((link) => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-sm text-muted-foreground hover:text-foreground"
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="mb-4 text-sm font-semibold">Legal</h3>
            <ul className="space-y-2">
              {footerLinks.legal.map((link) => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-sm text-muted-foreground hover:text-foreground"
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        </div>
        <Separator className="my-8" />
        <div className="flex flex-col items-center justify-between gap-4 md:flex-row">
          <p className="text-sm text-muted-foreground">
            &copy; {new Date().getFullYear()} Minisource. All rights reserved.
          </p>
          <div className="flex gap-4">
            <a
              href="https://github.com/minisource"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-muted-foreground hover:text-foreground"
            >
              GitHub
            </a>
            <a
              href="https://twitter.com/minisource"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-muted-foreground hover:text-foreground"
            >
              Twitter
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
