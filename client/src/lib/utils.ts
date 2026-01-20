import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

const MONTHS = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];

export function formatDTG(date: Date | string | number | null | undefined): string {
  if (date === null || date === undefined) return '—';
  const d = new Date(date);
  if (isNaN(d.getTime())) return '—';
  const day = String(d.getUTCDate()).padStart(2, '0');
  const hours = String(d.getUTCHours()).padStart(2, '0');
  const minutes = String(d.getUTCMinutes()).padStart(2, '0');
  const month = MONTHS[d.getUTCMonth()];
  const year = String(d.getUTCFullYear()).slice(-2);
  return `${day}${hours}${minutes}Z${month}${year}`;
}

export function formatDTGFull(date: Date | string | number | null | undefined): string {
  if (date === null || date === undefined) return '—';
  const d = new Date(date);
  if (isNaN(d.getTime())) return '—';
  const day = String(d.getUTCDate()).padStart(2, '0');
  const hours = String(d.getUTCHours()).padStart(2, '0');
  const minutes = String(d.getUTCMinutes()).padStart(2, '0');
  const seconds = String(d.getUTCSeconds()).padStart(2, '0');
  const month = MONTHS[d.getUTCMonth()];
  const year = d.getUTCFullYear();
  return `${day}${hours}${minutes}${seconds}Z ${month} ${year}`;
}

export function formatLocalDateTime(date: Date | string | number | null | undefined): string {
  if (date === null || date === undefined) return '—';
  const d = new Date(date);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short'
  });
}

export function parseDTG(dtg: string): Date | null {
  const match = dtg.match(/^(\d{2})(\d{2})(\d{2})Z([A-Z]{3})(\d{2})$/);
  if (!match) return null;
  const [, day, hours, minutes, month, year] = match;
  const monthIndex = MONTHS.indexOf(month);
  if (monthIndex === -1) return null;
  const fullYear = 2000 + parseInt(year, 10);
  return new Date(Date.UTC(fullYear, monthIndex, parseInt(day, 10), parseInt(hours, 10), parseInt(minutes, 10)));
}

export interface ReportSource {
  type: 'web_app_scan' | 'aev_evaluation' | 'full_assessment' | 'external_recon';
  id: string;
  targetName: string;
  timestamp: Date | string;
  findingsCount: number;
  evidenceCount?: number;
}

export function formatInputDate(date: Date | string | number): string {
  const d = new Date(date);
  if (isNaN(d.getTime())) return '';
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

export function isValidDate(date: Date | string | number | null | undefined): boolean {
  if (date === null || date === undefined) return false;
  const d = new Date(date);
  return !isNaN(d.getTime());
}

export function formatDTGWithLocal(date: Date | string | number): string {
  const d = new Date(date);
  if (isNaN(d.getTime())) return '—';
  const dtg = formatDTG(date);
  const local = formatLocalDateTime(date);
  return `${dtg} (${local})`;
}
