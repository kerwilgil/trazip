/**
 * Encodes an untrusted value as one RFC-4180 CSV cell while preventing
 * spreadsheet formula interpretation. Network names, capture metadata and
 * copied queries can all be attacker-controlled even in a desktop app.
 */
export function csvEscape(value: string): string {
  let safe = value;
  const significant = value.replace(/^[ \t\r\uFEFF]+/, '');
  if (/^[\t\r]/.test(value) || /^[=+\-@]/.test(significant)) safe = "'" + value;
  if (/[",\n]/.test(safe)) return '"' + safe.replace(/"/g, '""') + '"';
  return safe;
}
