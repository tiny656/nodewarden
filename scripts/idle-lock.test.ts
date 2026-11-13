import assert from 'node:assert/strict';
import test from 'node:test';
import { startIdleLock } from '../webapp/src/lib/idle-lock';

function fixture(timeoutMs = 60_000) {
  let time = 100_000;
  let timeouts = 0;
  let nextId = 0;
  const timers = new Map<number, { callback: () => void; due: number }>();
  class Target {
    visibilityState = 'visible';
    listeners = new Map<string, EventListener>();
    addEventListener(name: string, listener: EventListener) { this.listeners.set(name, listener); }
    removeEventListener(name: string) { this.listeners.delete(name); }
    emit(name: string, isTrusted = true) { this.listeners.get(name)?.({ isTrusted } as Event); }
    setTimeout(callback: () => void, ms: number) { const id = ++nextId; timers.set(id, { callback, due: time + ms }); return id; }
    clearTimeout(id: number) { timers.delete(id); }
  }
  const windowTarget = new Target();
  const documentTarget = new Target();
  const stop = startIdleLock({ timeoutMs, onTimeout: () => { timeouts += 1; }, now: () => time,
    windowTarget: windowTarget as unknown as Window, documentTarget: documentTarget as unknown as Document });
  return {
    windowTarget, documentTarget, timers, stop,
    advance(ms: number) { time += ms; },
    flush() { for (const [id, timer] of [...timers]) if (timer.due <= time) { timers.delete(id); timer.callback(); } },
    get timeouts() { return timeouts; },
    get remaining() { return [...timers.values()][0]?.due - time; },
  };
}

test('expired suspension locks immediately on visibility, focus, pageshow, or activity', () => {
  for (const event of ['visibilitychange', 'focus', 'pageshow', 'pointerdown', 'keydown']) {
    const f = fixture();
    f.advance(120_000); // Browser timers were suspended.
    (event === 'visibilitychange' ? f.documentTarget : f.windowTarget).emit(event);
    assert.equal(f.timeouts, 1, event);
    f.flush();
    f.windowTarget.emit('keydown');
    assert.equal(f.timeouts, 1);
    assert.equal(f.timers.size, 0);
    f.stop();
  }
});

test('returning to a nonexpired page does not renew its idle deadline', () => {
  const f = fixture();
  f.advance(45_000);
  f.windowTarget.emit('focus');
  f.documentTarget.emit('visibilitychange');
  assert.equal(f.remaining, 15_000);
  f.advance(15_000);
  f.flush();
  assert.equal(f.timeouts, 1);
  f.stop();
});

test('real foreground activity renews the deadline, synthetic or background activity does not', () => {
  const f = fixture();
  f.advance(20_000);
  f.windowTarget.emit('keydown', false);
  assert.equal(f.remaining, 40_000);
  f.documentTarget.visibilityState = 'hidden';
  f.windowTarget.emit('scroll');
  assert.equal(f.remaining, 40_000);
  f.documentTarget.visibilityState = 'visible';
  f.windowTarget.emit('pointerdown');
  assert.equal(f.remaining, 60_000);
  f.advance(60_000);
  f.flush();
  assert.equal(f.timeouts, 1);
  f.stop();
});

test('cleanup cancels timers and listeners; disabled timeouts do not schedule', () => {
  const f = fixture();
  f.stop();
  f.advance(120_000);
  f.flush();
  assert.equal(f.timeouts, 0);
  assert.equal(f.windowTarget.listeners.size, 0);
  assert.equal(f.documentTarget.listeners.size, 0);
  assert.equal(fixture(0).timers.size, 0);
});

test('moving the clock backwards cannot extend an unlocked session', () => {
  const f = fixture();
  f.advance(-60_000);
  f.windowTarget.emit('focus');
  assert.equal(f.timeouts, 1);
  f.stop();
});
