import { useEffect, useState } from 'react';

export function navigate(to: string) {
  history.pushState(null, '', to);
  window.dispatchEvent(new PopStateEvent('popstate'));
}
export function usePath(): string {
  const [p, setP] = useState(location.pathname);
  useEffect(() => {
    const f = () => setP(location.pathname);
    window.addEventListener('popstate', f);
    return () => window.removeEventListener('popstate', f);
  }, []);
  return p;
}
