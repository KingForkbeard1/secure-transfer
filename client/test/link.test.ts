import { describe, it, expect } from 'vitest';
import { parseLink } from '../src/link';

const id = 'FZpzw3mBJF9FcpazViN0RQ';
const key = 'A'.repeat(43);
describe('parseLink', () => {
  it('accepts a full URL, a relative path, and a link inside a chat message', () => {
    expect(parseLink(`https://example.com/s/${id}#${key}`)).toEqual({ id, key });
    expect(parseLink(`/s/${id}#${key}`)).toEqual({ id, key });
    expect(parseLink(`  here you go: http://localhost:3000/s/${id}#${key} thanks  `)).toEqual({ id, key });
  });
  it('rejects links missing the key, with a short key, or that are not links', () => {
    expect(parseLink(`https://example.com/s/${id}`)).toBeNull();
    expect(parseLink(`https://example.com/s/${id}#short`)).toBeNull();
    expect(parseLink(`https://example.com/s/${id}#${key}extra`)).toBeNull();
    expect(parseLink('hello')).toBeNull();
    expect(parseLink('')).toBeNull();
  });
});
