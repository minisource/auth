import { redirect } from 'next/navigation';

export default function HomePage() {
  // In Next.js 16 with basePath '/auth', redirect('/login') automatically
  // routes to '/auth/login'.
  redirect('/login');
}
