/**
 * Safe useInterval hook that avoids stale closures and guarantees cleanup on unmount.
 */

import { useEffect, useRef } from 'react';

export function useInterval(callback: () => void, delayMs: number | null): void {
  const savedCallback = useRef<() => void>(callback);

  // Remember the latest callback if it changes.
  useEffect(() => {
    savedCallback.current = callback;
  }, [callback]);

  // Set up the interval.
  useEffect(() => {
    if (delayMs === null || delayMs < 0) {
      return;
    }

    const tick = () => {
      savedCallback.current();
    };

    const id = setInterval(tick, delayMs);
    return () => clearInterval(id);
  }, [delayMs]);
}
