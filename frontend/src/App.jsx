import { useCallback, useEffect, useState } from 'react';
import { ShieldHalf, Search, Moon, Sun, Building2, UserRound, FlaskConical } from 'lucide-react';
import { NAV, PAGES, PERSONAS } from './nav.js';
import { useApi, storage } from './lib.jsx';
import CommandPalette from './components/CommandPalette.jsx';
import Overview from './pages/Overview.jsx';
import Agents from './pages/Agents.jsx';
import Copilot from './pages/Copilot.jsx';
import Vulnerabilities from './pages/Vulnerabilities.jsx';
import Assets from './pages/Assets.jsx';
import Remediation from './pages/Remediation.jsx';
import Correlation from './pages/Correlation.jsx';
import Sources from './pages/Sources.jsx';
import Reports from './pages/Reports.jsx';
import Pov from './pages/Pov.jsx';

const COMPONENTS = { overview: Overview, agents: Agents, copilot: Copilot, vulnerabilities: Vulnerabilities, assets: Assets, remediation: Remediation, correlation: Correlation, sources: Sources, reports: Reports, pov: Pov };

function parseHash() {
  const [path, qs] = window.location.hash.replace(/^#\/?/, '').split('?');
  return { page: COMPONENTS[path] ? path : 'overview', params: Object.fromEntries(new URLSearchParams(qs || '')) };
}

export default function App() {
  const [route, setRoute] = useState(parseHash);
  const [theme, setTheme] = useState(() => storage.get('eiq-theme', 'dark'));
  const [company, setCompany] = useState(() => storage.get('eiq-company', 'all'));
  const [persona, setPersona] = useState(() => storage.get('eiq-persona', 'ciso'));
  const [palette, setPalette] = useState(false);
  const meta = useApi('/meta');
  useEffect(() => { const id = setInterval(meta.reload, 10000); return () => clearInterval(id); }, [meta.reload]);

  useEffect(() => { document.documentElement.dataset.theme = theme; storage.set('eiq-theme', theme); }, [theme]);
  useEffect(() => { storage.set('eiq-company', company); }, [company]);
  useEffect(() => {
    const h = () => setRoute(parseHash());
    window.addEventListener('hashchange', h);
    return () => window.removeEventListener('hashchange', h);
  }, []);
  useEffect(() => {
    const h = (e) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPalette((p) => !p); } };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, []);

  const navigate = useCallback((page, params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== '')).toString();
    window.location.hash = `/${page}${qs ? `?${qs}` : ''}`;
    window.scrollTo({ top: 0 });
  }, []);

  const switchPersona = (id) => {
    const p = PERSONAS.find((x) => x.id === id);
    setPersona(id); storage.set('eiq-persona', id);
    setCompany(p.company);
    navigate(p.landing);
  };

  const Page = COMPONENTS[route.page];
  const info = PAGES[route.page];
  const companies = meta.data?.companies || [];
  const counts = meta.data?.counts || {};
  const trial = meta.data?.trial || { day: 23, length: 90 };

  return (
    <div className="app">
      <nav className="sidebar" aria-label="Main">
        <div className="brand">
          <div className="brand-mark"><ShieldHalf size={19} /></div>
          <div>
            <div className="brand-name">ExposureIQ</div>
            <div className="brand-sub">SHV Group · Vulnerability Intelligence</div>
          </div>
        </div>
        {NAV.map((g) => (
          <div key={g.group}>
            <div className="nav-group">{g.group}</div>
            {g.items.map((n) => (
              <button key={n.id} className={`nav-item ${n.ai ? 'ai-item' : ''} ${route.page === n.id ? 'active' : ''}`} onClick={() => navigate(n.id)}>
                <n.icon size={17} />{n.label}
                {n.id === 'agents' && counts.approvals > 0 && <span className="count" style={{ background: 'var(--ai)' }} title="Agent proposals waiting for approval">{counts.approvals}</span>}
                {n.id === 'vulnerabilities' && counts.p1 > 0 && <span className="count" title="CVEs with open P1 findings">{counts.p1}</span>}
                {n.id === 'correlation' && counts.review > 0 && <span className="count" style={{ background: 'var(--p3)', color: '#1a1300' }} title="Asset matches awaiting review">{counts.review}</span>}
              </button>
            ))}
          </div>
        ))}
        <div className="sidebar-foot">
          <button className="trial-card" style={{ width: '100%', textAlign: 'left' }} onClick={() => navigate('pov')}>
            <div className="row" style={{ gap: 6, fontSize: 12, fontWeight: 700 }}><FlaskConical size={14} style={{ color: 'var(--ai)' }} />MDVM trial</div>
            <div className="bar"><div style={{ width: `${(trial.day / trial.length) * 100}%` }} /></div>
            <div className="muted" style={{ fontSize: 11.5 }}>Day {trial.day} of {trial.length} · {trial.length - trial.day} days left</div>
          </button>
        </div>
      </nav>

      <div className="main">
        <header className="topbar">
          <div style={{ minWidth: 0 }}>
            <h1 className="page-title">{info.label}</h1>
            <div className="page-sub">{info.sub}</div>
          </div>
          <div className="spacer" />
          <button className="searchbox" onClick={() => setPalette(true)}><Search size={14} />Search or ask…<kbd>Ctrl K</kbd></button>
          <label className="row" style={{ gap: 6 }} title="Scope every view to one group company">
            <Building2 size={15} className="muted" />
            <select className="select" value={company} onChange={(e) => setCompany(e.target.value)} aria-label="Company scope">
              <option value="all">All SHV Group</option>
              {companies.map((c) => <option key={c.id} value={c.id}>{c.short}</option>)}
            </select>
          </label>
          <label className="row" style={{ gap: 6 }} title="Switch persona — changes the landing view">
            <UserRound size={15} className="muted" />
            <select className="select" value={persona} onChange={(e) => switchPersona(e.target.value)} aria-label="Persona">
              {PERSONAS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
            </select>
          </label>
          <span className="data-chip" title={meta.data?.dataMode === 'Live connectors' ? 'Syncing from your real Defender / Rapid7 / ServiceNow' : 'Built-in mock tenant: realistic API data. Add credentials in backend/.env to go live'}><span className="pulse" />{meta.data?.dataMode || 'Mock tenant'}{meta.data?.ai?.enabled ? ' · Gemini' : ''}</span>
          <button className="icon-btn" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label="Toggle theme">
            {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
          </button>
        </header>
        <main className="content">
          <Page key={route.page} company={company} setCompany={setCompany} params={route.params} navigate={navigate} persona={persona} companies={companies} />
        </main>
      </div>
      <CommandPalette open={palette} onClose={() => setPalette(false)} navigate={navigate} />
    </div>
  );
}
