import { LayoutDashboard, Bot, Sparkles, Bug, Server, Timer, GitMerge, Plug, FileText, FlaskConical } from 'lucide-react';

export const NAV = [
  { group: 'Command', items: [
    { id: 'overview', label: 'Command Center', icon: LayoutDashboard, sub: 'Live exposure across SHV Group, and how the data gets there' },
    { id: 'agents', label: 'AI Agents', icon: Bot, ai: true, sub: 'Four AI agents that triage, match, plan and answer, with every step traced' },
    { id: 'copilot', label: 'Ask ExposureIQ', icon: Sparkles, ai: true, sub: 'GenAI analyst grounded on your correlated vulnerability data' },
  ] },
  { group: 'Operate', items: [
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: Bug, sub: 'One de-duplicated, risk-ranked list across Rapid7 and Defender' },
    { id: 'assets', label: 'Assets & Coverage', icon: Server, sub: 'Unified inventory and scanner blind spots' },
    { id: 'remediation', label: 'Remediation & SLA', icon: Timer, sub: 'SHV SLA policy, accountability and overdue work' },
  ] },
  { group: 'Trust the data', items: [
    { id: 'correlation', label: 'Correlation Engine', icon: GitMerge, sub: 'How Rapid7 and Defender findings become one source of truth' },
    { id: 'sources', label: 'Data Sources', icon: Plug, sub: 'Connectors, sync health and the data pipeline' },
  ] },
  { group: 'Govern', items: [
    { id: 'reports', label: 'Reports', icon: FileText, sub: 'Automated operational, executive and audit reporting' },
    { id: 'pov', label: 'Trial & Value Tracker', icon: FlaskConical, sub: '90-day MDVM proof of value — plan, success criteria, prerequisites' },
  ] },
];

export const PAGES = Object.fromEntries(NAV.flatMap((g) => g.items).map((i) => [i.id, i]));

export const PERSONAS = [
  { id: 'ciso', label: 'Group CISO', desc: 'Enterprise risk & board reporting', landing: 'overview', company: 'all' },
  { id: 'analyst', label: 'Security Analyst', desc: 'Triage & correlation', landing: 'vulnerabilities', company: 'all' },
  { id: 'bu', label: 'BU IT Lead · Mammoet', desc: 'Remediation owner', landing: 'remediation', company: 'mammoet' },
];
