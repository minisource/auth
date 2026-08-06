import { redirect } from 'next/navigation';

export default function HomePage() {
  // basePath '/auth' is NOT auto-applied to server-side redirect(), so the
  // full path is required here.
  redirect('/auth/login');
}
