import React, { useEffect, useRef } from 'react';
import { ScanEvent } from '../api/types';

interface EventLogProps {
  events: ScanEvent[];
}

export const EventLog: React.FC<EventLogProps> = ({ events }) => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [events]);

  if (events.length === 0) {
    return (
      <div className="event-log-container empty">
        <p className="empty-message">No scan events recorded yet.</p>
      </div>
    );
  }

  return (
    <div className="event-log-container" ref={containerRef}>
      <table className="event-log-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Stage</th>
            <th>%</th>
            <th>Level</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {events.map((ev) => {
            const timeStr = new Date(ev.created_at).toLocaleTimeString();
            return (
              <tr key={ev.id} className={`event-level-${ev.level.toLowerCase()}`}>
                <td className="event-time">{timeStr}</td>
                <td className="event-stage">{ev.stage}</td>
                <td className="event-pct">{ev.percent}%</td>
                <td className="event-level-badge">{ev.level.toUpperCase()}</td>
                <td className="event-msg">{ev.message}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};
