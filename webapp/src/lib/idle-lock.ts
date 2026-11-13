interface IdleLockOptions {
  timeoutMs: number;
  onTimeout: () => void;
  now?: () => number;
  windowTarget?: Window;
  documentTarget?: Document;
}

/** Deadline-based locking survives throttled timers, suspension and bfcache. */
export function startIdleLock({
  timeoutMs,
  onTimeout,
  now = Date.now,
  windowTarget = window,
  documentTarget = document,
}: IdleLockOptions): () => void {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) return () => {};
  let lastActivityAt = now();
  let deadline = lastActivityAt + timeoutMs;
  let timer: number | null = null;
  let stopped = false;
  const clearTimer = () => {
    if (timer !== null) windowTarget.clearTimeout(timer);
    timer = null;
  };
  const checkDeadline = () => {
    if (stopped) return true;
    const time = now();
    // A backwards wall-clock change must not extend an unlocked session.
    if (time >= deadline || time < lastActivityAt) {
      stopped = true;
      clearTimer();
      onTimeout();
      return true;
    }
    return false;
  };
  const schedule = () => {
    clearTimer();
    timer = windowTarget.setTimeout(() => {
      if (!checkDeadline()) schedule();
    }, Math.max(0, deadline - now()));
  };
  const onActivity = (event: Event) => {
    // Check expiry before any activity can grant another timeout interval.
    if (checkDeadline()) return;
    if (!event.isTrusted || documentTarget.visibilityState !== 'visible') return;
    const time = now();
    if (time - lastActivityAt < 1000) return;
    lastActivityAt = time;
    deadline = time + timeoutMs;
    schedule();
  };
  const onResume = () => {
    if (!checkDeadline()) schedule();
  };
  const onVisibilityChange = () => {
    if (documentTarget.visibilityState === 'visible') onResume();
  };
  const activityEvents = ['pointerdown', 'keydown', 'scroll', 'touchstart'];
  for (const event of activityEvents) windowTarget.addEventListener(event, onActivity, { passive: true, capture: true });
  windowTarget.addEventListener('focus', onResume);
  windowTarget.addEventListener('pageshow', onResume);
  documentTarget.addEventListener('visibilitychange', onVisibilityChange);
  schedule();
  return () => {
    stopped = true;
    clearTimer();
    for (const event of activityEvents) windowTarget.removeEventListener(event, onActivity, true);
    windowTarget.removeEventListener('focus', onResume);
    windowTarget.removeEventListener('pageshow', onResume);
    documentTarget.removeEventListener('visibilitychange', onVisibilityChange);
  };
}
