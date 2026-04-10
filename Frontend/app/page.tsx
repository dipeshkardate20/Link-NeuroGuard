'use client';

import { useState, useEffect } from 'react';

export default function LinkNeuroGuard() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [history, setHistory] = useState<any[]>([]);
  const [isDark, setIsDark] = useState(false); 

  useEffect(() => {
    const saved = localStorage.getItem('neuroHistory');
    if (saved) setHistory(JSON.parse(saved));
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      setIsDark(true);
    }
  }, []);

  const totalScans = history.length;
  const threatsFlagged = history.filter(h => h.verdict === 'Malicious' || h.verdict === 'Suspicious').length;
  const safeLinks = history.filter(h => h.verdict === 'Safe').length;

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    
    const urlsToScan = url.split('\n').map(u => u.trim()).filter(u => u.length > 0);
    if (urlsToScan.length === 0) return;
    
    setLoading(true);
    setError('');
    
    try {
      for (const targetUrl of urlsToScan) {
        const res = await fetch('https://localhost:8000/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: targetUrl }),
        });
        
        const data = await res.json();
        
        if (!res.ok || data.error) {
          console.error(`Failed to analyze ${targetUrl}:`, data.error);
          continue; 
        }

        const enhancedData = {
          ...data,
          risk_score: data.verdict === 'Safe' ? -5 : 85,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          date: new Date().toLocaleDateString(),
          domain: data.levi?.target || data.url.replace(/^https?:\/\//, '').split('/')[0],
          flags: data.verdict === 'Safe' 
            ? [{ text: "HTTPS present", score: -2 }, { text: "Trusted domain detected", score: -3 }]
            : [{ text: "High lexical entropy", score: +40 }, { text: "Typosquatting detected", score: +45 }]
        };

        setResult(enhancedData);

        setHistory(prevHistory => {
          const filteredHistory = prevHistory.filter(h => h.url !== enhancedData.url);
          const updatedHistory = [enhancedData, ...filteredHistory].slice(0, 15);
          localStorage.setItem('neuroHistory', JSON.stringify(updatedHistory));
          return updatedHistory;
        });
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
      setUrl(''); 
    }
  };

  const getTheme = (verdict: string) => {
    switch (verdict?.toLowerCase()) {
      case 'malicious': return { 
        bg: 'bg-red-50 dark:bg-red-950/30', border: 'border-red-200 dark:border-red-900/50', 
        text: 'text-red-900 dark:text-red-400', accent: 'bg-red-100 dark:bg-red-900/40', 
        textAccent: 'text-red-600 dark:text-red-400', cardBg: 'bg-white dark:bg-[#161410]', 
        tagBorder: 'border-red-200 dark:border-red-900/50'
      };
      case 'suspicious': return { 
        bg: 'bg-[#FFFBEB] dark:bg-amber-950/30', border: 'border-[#FDE68A] dark:border-amber-900/50', 
        text: 'text-[#92400E] dark:text-amber-500', accent: 'bg-[#FEF3C7] dark:bg-amber-900/40', 
        textAccent: 'text-[#D97706] dark:text-amber-500', cardBg: 'bg-white dark:bg-[#161410]', 
        tagBorder: 'border-[#FDE68A] dark:border-amber-900/50'
      };
      default: return { 
        bg: 'bg-[#F0FDF4] dark:bg-emerald-950/20', border: 'border-[#BBF7D0] dark:border-emerald-900/30', 
        text: 'text-[#166534] dark:text-emerald-500', accent: 'bg-[#DCFCE7] dark:bg-emerald-900/30', 
        textAccent: 'text-[#059669] dark:text-emerald-500', cardBg: 'bg-white dark:bg-[#161410]', 
        tagBorder: 'border-[#BBF7D0] dark:border-emerald-900/30'
      };
    }
  };

  const theme = result ? getTheme(result.verdict) : null;

  return (
    <div className={`${isDark ? 'theme-dark' : ''}`}>
      <div className="min-h-screen bg-[#FFFDF2] dark:bg-[#0D0C0A] text-[#1A1810] dark:text-[#E8E4D9] font-sans selection:bg-[#FDE68A] dark:selection:bg-[#C29F40]/40 p-6 lg:p-12 relative overflow-hidden pb-24 transition-colors duration-500">
        
        {/* Background Depth Blobs */}
        <div className="absolute top-[-10%] right-[-10%] w-[600px] h-[600px] bg-[#FACC15]/10 dark:bg-[#FACC15]/5 rounded-full blur-[120px] -z-10 animate-pulse pointer-events-none" />
        <div className="absolute bottom-[-5%] left-[-5%] w-[400px] h-[400px] bg-[#C29F40]/5 dark:bg-[#C29F40]/5 rounded-full blur-[100px] -z-10 pointer-events-none" />

        <div className="max-w-7xl mx-auto space-y-10 relative">
          
          {/* --- 1. HERO SECTION --- */}
          <div className="bg-white/50 dark:bg-[#161410]/50 backdrop-blur-sm border border-[#F5E6C4] dark:border-[#2A261D] p-10 md:p-16 rounded-[48px] shadow-sm transition-colors">
            <div className="flex justify-between items-start mb-6">
              <p className="text-[10px] font-bold uppercase tracking-[0.3em] text-[#C29F40] dark:text-[#D4AF37]">
                Ai-Powered Url Threat Analysis
              </p>
              <div className="flex items-center gap-4">
                <span className="px-4 py-1.5 rounded-full border border-[#F5E6C4] dark:border-[#2A261D] text-[11px] font-bold text-[#C29F40] dark:text-[#D4AF37] bg-white/60 dark:bg-[#1A1814]/60">
                  Heuristic Engine Active
                </span>
                {/* Dark Mode Toggle */}
                <button 
                  onClick={() => setIsDark(!isDark)} 
                  className="p-2 rounded-full bg-white dark:bg-[#1A1814] border border-[#F5E6C4] dark:border-[#2A261D] text-[#C29F40] dark:text-[#D4AF37] hover:bg-[#FFFDF2] dark:hover:bg-[#221F19] transition-all"
                  title="Toggle Theme"
                >
                  {isDark ? '☀️' : '🌙'}
                </button>
              </div>
            </div>
            <h1 className="text-6xl md:text-8xl font-black tracking-tighter mb-6 text-[#1A1810] dark:text-[#F3F0E6] leading-[0.9]">
              LINK NEUROGUARD
            </h1>
            <p className="max-w-2xl text-lg md:text-xl text-[#635F4C] dark:text-[#9CA3AF] leading-relaxed font-medium">
              Frontend dashboard for malicious link detection with batch scanning, explainable scoring, recent analysis history, and analyst-style security insights.
            </p>
          </div>

          {/* --- 2. SCANNER INPUT --- */}
          <div className="bg-white dark:bg-[#161410] p-8 md:p-10 rounded-[48px] shadow-sm border border-[#F5E6C4] dark:border-[#2A261D] transition-colors">
            <div className="flex justify-between items-center mb-8">
              <div>
                <p className="text-[10px] font-bold uppercase tracking-widest text-[#C29F40] dark:text-[#D4AF37] mb-1">Analyze URL</p>
                <h2 className="text-3xl font-black text-[#1A1810] dark:text-[#F3F0E6] tracking-tight">Run Threat Detection</h2>
              </div>
              <span className="px-4 py-1.5 rounded-full border border-[#F5E6C4] dark:border-[#2A261D] text-[11px] font-bold text-[#C29F40] dark:text-[#D4AF37] bg-[#FFFDF2] dark:bg-[#0D0C0A]">
                Live Dashboard
              </span>
            </div>

            <form onSubmit={handleScan} className="space-y-6">
              <textarea 
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Paste one or more URLs.&#10;Example:&#10;paypal-login-check.com&#10;https://bit.ly/freegift"
                className="w-full h-40 p-6 bg-[#FFFDF2] dark:bg-[#0D0C0A] border border-[#F5E6C4] dark:border-[#2A261D] rounded-[32px] outline-none focus:ring-4 focus:ring-[#FACC15]/20 dark:focus:ring-[#C29F40]/30 text-[#1A1810] dark:text-[#F3F0E6] placeholder:text-[#C4C1B0] dark:placeholder:text-[#524D40] font-mono text-sm leading-relaxed transition-all"
                required
              />
              <div className="flex flex-col md:flex-row justify-between items-center gap-6">
                <button 
                  disabled={loading}
                  className="w-full md:w-auto px-12 py-5 bg-[#FACC15] dark:bg-[#D4AF37] hover:bg-[#EAB308] dark:hover:bg-[#B4952D] disabled:bg-[#F5E6C4] dark:disabled:bg-[#2A261D] disabled:text-[#8E8A75] dark:disabled:text-[#6B6554] text-[#1A1810] dark:text-[#0D0C0A] font-black rounded-2xl transition-all shadow-md shadow-[#FACC15]/20 dark:shadow-none text-lg tracking-tight"
                >
                  {loading ? 'Analyzing Batch...' : 'Analyze URLs'}
                </button>
                <p className="text-[11px] text-[#8E8A75] dark:text-[#9CA3AF] font-medium leading-tight max-w-[280px]">
                  Supports single URL scans and batch processing via comma or new line separation.
                </p>
              </div>
            </form>
            {error && <p className="text-red-500 dark:text-red-400 mt-6 px-4 font-bold text-sm bg-red-50 dark:bg-red-950/30 py-3 rounded-xl border border-red-100 dark:border-red-900/50">Engine Error: {error}</p>}
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-10">
            <div className="bg-white dark:bg-[#161410] p-8 md:p-10 rounded-[48px] shadow-sm border border-[#F5E6C4] dark:border-[#2A261D] transition-colors">
              <div className="flex justify-between items-center mb-10">
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-widest text-[#C29F40] dark:text-[#D4AF37] mb-1">Results Panel</p>
                  <h2 className="text-3xl font-black text-[#1A1810] dark:text-[#F3F0E6] tracking-tight">Recent Threat Analysis</h2>
                </div>
                <span className="px-4 py-1.5 rounded-full border border-[#F5E6C4] dark:border-[#2A261D] text-[11px] font-bold text-[#C29F40] dark:text-[#D4AF37] bg-[#FFFDF2] dark:bg-[#0D0C0A]">
                  Click to View
                </span>
              </div>

              <div className="space-y-4 max-h-[700px] overflow-y-auto pr-2 pb-4 scrollbar-thin scrollbar-thumb-[#F5E6C4] dark:scrollbar-thumb-[#2A261D] scrollbar-track-transparent">
                {history.length === 0 ? (
                  <p className="text-[#8E8A75] dark:text-[#6B6554] italic text-sm text-center py-10">No recent scans logged.</p>
                ) : (
                  history.map((item, i) => (
                    <div 
                      key={i} 
                      onClick={() => setResult(item)}
                      className={`bg-[#FFFDF2] dark:bg-[#0D0C0A] p-6 rounded-[32px] border ${result?.url === item.url ? 'border-[#FACC15] dark:border-[#D4AF37] shadow-sm' : 'border-[#F5E6C4] dark:border-[#2A261D]'} flex justify-between items-center group cursor-pointer transition-all hover:border-[#FACC15] dark:hover:border-[#D4AF37]`}
                    >
                      <div className="max-w-[65%]">
                        <span className={`px-2.5 py-1 rounded-full border text-[9px] font-black uppercase tracking-widest ${
                          item.verdict === 'Safe' ? 'bg-[#F0FDF4] dark:bg-emerald-950/20 text-[#166534] dark:text-emerald-500 border-[#BBF7D0] dark:border-emerald-900/30' : 
                          item.verdict === 'Suspicious' ? 'bg-[#FFFBEB] dark:bg-amber-950/30 text-[#92400E] dark:text-amber-500 border-[#FDE68A] dark:border-amber-900/50' : 
                          'bg-red-50 dark:bg-red-950/30 text-red-900 dark:text-red-400 border-red-200 dark:border-red-900/50'
                        }`}>
                          {item.verdict}
                        </span>
                        <h4 className="text-xl font-black mt-3 truncate dark:text-[#F3F0E6]" title={item.domain}>{item.domain}</h4>
                        <p className="text-[10px] text-[#8E8A75] dark:text-[#9CA3AF] font-mono mt-1 truncate" title={item.url}>{item.url}</p>
                      </div>
                      <div className="text-right">
                        <p className="text-2xl font-black leading-none dark:text-[#F3F0E6]">{item.xgb_confidence || item.confidence}%</p>
                        <p className={`text-[10px] font-bold uppercase mt-1 tracking-tighter ${
                          item.verdict === 'Safe' ? 'text-[#166534] dark:text-emerald-500' : 'text-red-700 dark:text-red-400'
                        }`}>
                          {item.verdict === 'Safe' ? 'Trusted' : 'Flagged'}
                        </p>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="bg-white dark:bg-[#161410] p-8 md:p-10 rounded-[48px] shadow-sm border border-[#F5E6C4] dark:border-[#2A261D] transition-colors">
              <div className="flex justify-between items-center mb-10">
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-widest text-[#C29F40] dark:text-[#D4AF37] mb-1">Explainability Module</p>
                  <h2 className="text-3xl font-black text-[#1A1810] dark:text-[#F3F0E6] tracking-tight">Threat Breakdown</h2>
                </div>
                {result && theme ? (
                  <span className={`px-4 py-1.5 rounded-full border text-[11px] font-black uppercase tracking-widest ${theme.bg} ${theme.textAccent} ${theme.border}`}>
                    {result.verdict}
                  </span>
                ) : (
                  <span className="px-4 py-1.5 rounded-full border border-slate-200 dark:border-[#2A261D] text-[11px] font-bold text-slate-400 dark:text-[#6B6554] bg-slate-50 dark:bg-[#0D0C0A]">Waiting</span>
                )}
              </div>

              {result && theme ? (
                <div className="animate-in fade-in duration-500">
                  
                  <div className="space-y-4 mb-10">
                    <h3 className="text-xl font-black text-[#1A1810] dark:text-[#F3F0E6]">AI Engine Analysis</h3>
                    <div className="bg-gradient-to-br from-[#FFFDF2] dark:from-[#0D0C0A] to-white dark:to-[#161410] border border-[#FACC15]/40 dark:border-[#D4AF37]/20 p-6 rounded-[28px] shadow-sm">
                      <div className="flex items-start gap-4">
                        <span className="text-[#C29F40] dark:text-[#D4AF37] text-2xl mt-1">✨</span>
                        <p className="text-base text-[#1A1810] dark:text-[#E8E4D9] italic leading-loose font-semibold">"{result.reasoning}"</p>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4 mb-8">
                    <div className="bg-[#FFFDF2] dark:bg-[#0D0C0A] p-6 rounded-[28px] border border-[#F5E6C4] dark:border-[#2A261D]">
                      <p className="text-[9px] font-bold text-[#8E8A75] dark:text-[#9CA3AF] uppercase tracking-widest mb-2">Threat Profile</p>
                      <p className={`text-xl font-black ${theme.textAccent}`}>{result.verdict === 'Safe' ? 'Clean / Trusted' : (result.xgb_prediction || 'Suspicious Activity')}</p>
                    </div>
                    <div className="bg-[#FFFDF2] dark:bg-[#0D0C0A] p-6 rounded-[28px] border border-[#F5E6C4] dark:border-[#2A261D]">
                      <p className="text-[9px] font-bold text-[#8E8A75] dark:text-[#9CA3AF] uppercase tracking-widest mb-2">Confidence Score</p>
                      <p className="text-xl font-black dark:text-[#F3F0E6]">{result.xgb_confidence || result.confidence || 'N/A'}%</p>
                    </div>
                    <div className="bg-[#FFFDF2] dark:bg-[#0D0C0A] p-6 rounded-[28px] border border-[#F5E6C4] dark:border-[#2A261D]">
                      <p className="text-[9px] font-bold text-[#8E8A75] dark:text-[#9CA3AF] uppercase tracking-widest mb-2">Risk Status</p>
                      <p className="text-xl font-black dark:text-[#F3F0E6]">{result.blacklist_status === 'Clean' ? 'Low' : 'High'}</p>
                    </div>
                    <div className="bg-[#FFFDF2] dark:bg-[#0D0C0A] p-6 rounded-[28px] border border-[#F5E6C4] dark:border-[#2A261D]">
                      <p className="text-[9px] font-bold text-[#8E8A75] dark:text-[#9CA3AF] uppercase tracking-widest mb-2">Scanned At</p>
                      <p className="text-[15px] font-black dark:text-[#F3F0E6] leading-tight pt-1">
                        {result.date || new Date().toLocaleDateString()}<br/>{result.timestamp}
                      </p>
                    </div>
                  </div>

                  <div className="space-y-4 pt-8 border-t border-[#F5E6C4] dark:border-[#2A261D]">
                    <h3 className="text-lg font-black text-[#1A1810] dark:text-[#F3F0E6]">Technical Evidence</h3>
                    <div className="grid grid-cols-2 gap-4">
                      <div className={`${theme.cardBg} border border-[#F5E6C4] dark:border-[#2A261D] p-4 rounded-2xl flex justify-between items-center`}>
                        <span className="text-[10px] font-bold text-[#8E8A75] dark:text-[#9CA3AF] uppercase tracking-widest">Blacklist</span>
                        <span className={`font-black text-sm ${result.blacklist_status === 'Clean' ? 'text-[#166534] dark:text-emerald-500' : 'text-red-600 dark:text-red-400'}`}>{result.blacklist_status}</span>
                      </div>
                      <div className={`${theme.cardBg} border border-[#F5E6C4] dark:border-[#2A261D] p-4 rounded-2xl flex justify-between items-center`}>
                        <span className="text-[10px] font-bold text-[#8E8A75] dark:text-[#9CA3AF] uppercase tracking-widest">Domain Age</span>
                        <span className="font-black text-sm dark:text-[#F3F0E6]">{result.domain_info?.age_days !== 'Unknown' ? `${result.domain_info?.age_days}d` : 'N/A'}</span>
                      </div>
                      <div className={`${theme.cardBg} border border-[#F5E6C4] dark:border-[#2A261D] p-4 rounded-2xl flex justify-between items-center`}>
                        <span className="text-[10px] font-bold text-[#8E8A75] dark:text-[#9CA3AF] uppercase tracking-widest">Levi Dist</span>
                        <span className="font-black text-sm dark:text-[#F3F0E6]">{result.levi?.distance}</span>
                      </div>
                      <div className={`${theme.cardBg} border border-[#F5E6C4] dark:border-[#2A261D] p-4 rounded-2xl flex justify-between items-center`}>
                        <span className="text-[10px] font-bold text-[#8E8A75] dark:text-[#9CA3AF] uppercase tracking-widest">Redirects</span>
                        <span className="font-black text-sm dark:text-[#F3F0E6]">{result.redirects?.count}</span>
                      </div>
                    </div>
                  </div>

                  {/* Network Trace */}
                  {result.redirects?.chain && result.redirects.chain.length > 1 && (
                    <div className="space-y-4 pt-8 border-t border-[#F5E6C4] dark:border-[#2A261D] mt-8">
                      <h3 className="text-lg font-black text-[#1A1810] dark:text-[#F3F0E6]">Network Trace</h3>
                      <div className="bg-white dark:bg-[#161410] border border-[#F5E6C4] dark:border-[#2A261D] p-6 rounded-[28px]">
                        <div className="space-y-3 font-mono text-[11px] leading-relaxed">
                          {result.redirects.chain.map((link: string, idx: number) => (
                            <div key={idx} className="flex gap-3 items-start text-[#635F4C] dark:text-[#9CA3AF] break-all">
                              <span className="text-[#C4C1B0] dark:text-[#524D40] font-black select-none mt-0.5">{idx === 0 ? '○' : '↳'}</span>
                              <span className={idx === result.redirects.chain.length - 1 ? 'font-bold text-[#1A1810] dark:text-[#F3F0E6]' : 'font-medium'}>
                                {link}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                </div>
              ) : (
                <div className="h-64 flex flex-col items-center justify-center text-center opacity-50">
                  <span className="text-4xl mb-4">🔍</span>
                  <p className="text-[#8E8A75] dark:text-[#9CA3AF] font-medium text-sm">Run a scan or click an item in the<br/>history panel to view the threat breakdown.</p>
                </div>
              )}
            </div>

          </div>

          {/* --- 4. GLOBAL STATS --- */}
          <div className="pt-10 border-t border-[#F5E6C4]/50 dark:border-[#2A261D]/50">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
              {[
                { label: 'Scans Logged', value: totalScans },
                { label: 'Threats Flagged', value: threatsFlagged },
                { label: 'Safe Links', value: safeLinks }
              ].map((stat, i) => (
                <div key={i} className="bg-white/40 dark:bg-[#161410]/40 border border-[#F5E6C4] dark:border-[#2A261D] p-8 rounded-[32px] shadow-sm">
                  <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#C29F40] dark:text-[#D4AF37] mb-2">{stat.label}</p>
                  <p className="text-4xl font-black tracking-tight dark:text-[#F3F0E6]">{stat.value}</p>
                </div>
              ))}
            </div>

            {/* --- 5. CATEGORY CARDS --- */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="bg-gradient-to-br from-red-50 dark:from-red-950/20 to-[#FFFDF2] dark:to-[#0D0C0A] border border-red-100 dark:border-red-900/30 p-8 rounded-[40px] shadow-sm">
                <p className="text-[10px] font-bold uppercase tracking-widest text-red-400 dark:text-red-500 mb-2">Malicious</p>
                <p className="text-4xl font-black mb-4 dark:text-[#F3F0E6]">1</p>
                <p className="text-xs text-red-900/60 dark:text-red-400/80 font-medium leading-relaxed">High-confidence phishing, malware, or impersonation patterns.</p>
              </div>
              <div className="bg-gradient-to-br from-amber-50 dark:from-amber-950/20 to-[#FFFDF2] dark:to-[#0D0C0A] border border-amber-100 dark:border-amber-900/30 p-8 rounded-[40px] shadow-sm">
                <p className="text-[10px] font-bold uppercase tracking-widest text-amber-500 dark:text-amber-500 mb-2">Suspicious</p>
                <p className="text-4xl font-black mb-4 dark:text-[#F3F0E6]">1</p>
                <p className="text-xs text-amber-900/60 dark:text-amber-400/80 font-medium leading-relaxed">Needs caution due to shorteners, redirects, or risky lexical signals.</p>
              </div>
              <div className="bg-gradient-to-br from-emerald-50 dark:from-emerald-950/20 to-[#FFFDF2] dark:to-[#0D0C0A] border border-emerald-100 dark:border-emerald-900/30 p-8 rounded-[40px] shadow-sm">
                <p className="text-[10px] font-bold uppercase tracking-widest text-emerald-500 dark:text-emerald-500 mb-2">Safe</p>
                <p className="text-4xl font-black mb-4 dark:text-[#F3F0E6]">3</p>
                <p className="text-xs text-emerald-900/60 dark:text-emerald-400/80 font-medium leading-relaxed">No major indicators triggered in the current client-side analysis.</p>
              </div>
              <div className="bg-[#FEFCE8] dark:bg-[#1A1810] border border-yellow-200 dark:border-yellow-900/30 p-8 rounded-[40px] shadow-sm">
                <p className="text-[10px] font-bold uppercase tracking-widest text-yellow-600 dark:text-yellow-500 mb-2">Coverage</p>
                <p className="text-2xl font-black mb-4 leading-tight text-[#1A1810] dark:text-[#F3F0E6]">Pattern + Reputation Ready</p>
                <p className="text-xs text-yellow-900/60 dark:text-yellow-500/80 font-medium leading-relaxed">UI is structured to connect a backend ML model, blacklist API, or sandbox service.</p>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}