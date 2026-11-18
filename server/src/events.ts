import type { Response } from 'express';

/** Server-sent events: tells a signed-in browser "something changed, refresh". Carries no message content. */
export class EventHub {
  private clients = new Map<string, Set<Response>>();

  add(userId: string, res: Response): void {
    res.status(200).set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    res.flushHeaders();
    res.write('retry: 3000\n\n');
    const set = this.clients.get(userId) ?? new Set<Response>();
    if (set.size >= 5) { const oldest = set.values().next().value as Response; set.delete(oldest); oldest.end(); }
    set.add(res);
    this.clients.set(userId, set);
    const beat = setInterval(() => res.write(': keep-alive\n\n'), 25_000);
    res.on('close', () => { clearInterval(beat); set.delete(res); if (!set.size) this.clients.delete(userId); });
  }
  notify(userIds: string[]): void {
    for (const id of new Set(userIds)) for (const res of this.clients.get(id) ?? []) res.write('data: {"t":"change"}\n\n');
  }
  closeAll(): void {
    for (const set of this.clients.values()) for (const res of set) res.end();
    this.clients.clear();
  }
}
