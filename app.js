document.addEventListener('DOMContentLoaded', () => {
    let threatsData = { nvd_cves: [], cisa_kev: [], last_updated: null };
    let newsData = { hacker_news: [], reddit_netsec: [], last_updated: null };
    let watchlist = JSON.parse(localStorage.getItem('threatWatchlist') || '[]');
    let threatHistory = [];
    let timelineChart = null;
    let activeFilters = 0;

    // ===== DOM ELEMENTS =====
    const severityFilter = document.getElementById('severity-filter');
    const severityValue = document.getElementById('severity-value');
    const techSearch = document.getElementById('tech-search');
    const sourceFilter = document.getElementById('source-filter');
    const vectorFilter = document.getElementById('vector-filter');
    const threatCardsContainer = document.getElementById('threat-cards-container');
    const watchlistContainer = document.getElementById('watchlist-container');
    const lastUpdatedTime = document.getElementById('last-updated-time');
    const liveTime = document.getElementById('live-time');
    const filterBadge = document.getElementById('filter-count');
    const btnResetFilters = document.getElementById('btn-reset-filters');
    const btnTelegramNotify = document.getElementById('btn-telegram-notify');
    const btnExportReport = document.getElementById('btn-export-report');
    const cveModal = document.getElementById('cveModal');
    const telegramModal = document.getElementById('telegramModal');
    const btnCloseModal = document.getElementById('btn-close-modal');
    const btnCloseTelegramModal = document.getElementById('btn-close-telegram-modal');
    const btnRefresh = document.getElementById('btn-refresh');
    const themeToggle = document.getElementById('theme-toggle');

    // ===== THEME TOGGLE =====
    const currentTheme = localStorage.getItem('theme') || 'dark';
    document.body.classList.toggle('light-mode', currentTheme === 'light');
    themeToggle.querySelector('i').className = currentTheme === 'light' ? 'fas fa-sun' : 'fas fa-moon';

    themeToggle.addEventListener('click', () => {
        const isLight = document.body.classList.toggle('light-mode');
        const newTheme = isLight ? 'light' : 'dark';
        localStorage.setItem('theme', newTheme);
        themeToggle.querySelector('i').className = isLight ? 'fas fa-sun' : 'fas fa-moon';
    });

    // ===== REFRESH DATA =====
    btnRefresh.addEventListener('click', () => {
        const icon = btnRefresh.querySelector('i');
        icon.classList.add('fa-spin');
        fetchData().then(() => {
            setTimeout(() => icon.classList.remove('fa-spin'), 1000);
        });
    });

    // ===== LIVE CLOCK =====
    function updateLiveClock() {
        const now = new Date();
        liveTime.textContent = now.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
    setInterval(updateLiveClock, 1000);
    updateLiveClock();

    // ===== TAB SWITCHING =====
    const tabBtns = document.querySelectorAll('.tab-btn');
    const mobileNavItems = document.querySelectorAll('.mobile-nav-item');
    const tabContents = document.querySelectorAll('.tab-content');

    function switchTab(tabName) {
        tabBtns.forEach(b => b.classList.remove('active'));
        mobileNavItems.forEach(m => m.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));
        
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        document.getElementById(tabName).classList.add('active');
        
        // Mobile nav
        const mobileItem = document.querySelector(`.mobile-nav-item[data-tab="${tabName}"]`);
        if (mobileItem) mobileItem.classList.add('active');
    }

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });

    mobileNavItems.forEach(item => {
        item.addEventListener('click', () => switchTab(item.dataset.tab));
    });

    // ===== KEYBOARD SHORTCUTS =====
    document.addEventListener('keydown', (e) => {
        if (e.key === '1') switchTab('threats');
        if (e.key === '2') switchTab('kev');
        if (e.key === '3') switchTab('news');
    });

    // ===== MODAL FUNCTIONS =====
    function openCveModal(cveData) {
        if (!cveData || (!cveData.cve && !cveData.cveID)) return;

        // Se è un dato KEV ma non ha i dettagli NVD, cerchiamo se esiste nel database NVD caricato
        if (cveData.cveID && !cveData.cve) {
            const foundInNvd = threatsData.nvd_cves.find(item => item.cve.id === cveData.cveID);
            if (foundInNvd) {
                cveData = foundInNvd;
            }
        }

        const isNvd = !!cveData.cve;
        const cveId = isNvd ? cveData.cve.id : cveData.cveID;
        const description = isNvd 
            ? (cveData.cve.descriptions.find(d => d.lang === 'en')?.value || 'Nessuna descrizione disponibile.')
            : (cveData.shortDescription || 'Nessuna descrizione disponibile.');
        
        document.getElementById('modal-cve-id').textContent = cveId;
        document.getElementById('modal-description').textContent = description;
        
        if (isNvd) {
            const cve = cveData.cve;
            const metrics = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
            const vector = metrics?.vectorString || 'N/A';
            
            // CVSS Vector breakdown
            const vectorParts = vector.split('/');
            const vectorHtml = vectorParts.map(part => `<div class="vector-pill">${part}</div>`).join('');
            document.getElementById('modal-cvss-vector').innerHTML = vectorHtml;
            
            // Affected versions
            const affectedVersions = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch || [];
            const versionsHtml = affectedVersions.slice(0, 5).map(v => `<div class="affected-versions">${v.criteria}</div>`).join('');
            document.getElementById('modal-affected-versions').innerHTML = versionsHtml || '<p>Non disponibile</p>';
            
            // References
            const references = cve.references || [];
            const referencesHtml = references.map(ref => `<li><a href="${ref.url}" target="_blank">${ref.url}</a></li>`).join('');
            document.getElementById('modal-references').innerHTML = referencesHtml || '<li>Nessun riferimento disponibile</li>';
        } else {
            // Dati KEV limitati
            document.getElementById('modal-cvss-vector').innerHTML = '<div class="vector-pill">Sfruttato Attivamente</div>';
            document.getElementById('modal-affected-versions').innerHTML = `<div class="affected-versions">${cveData.vendorProject} - ${cveData.product}</div>`;
            document.getElementById('modal-references').innerHTML = `<li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank">Vedi nel catalogo CISA</a></li>`;
        }
        
        // Links
        document.getElementById('btn-nvd-link').href = `https://nvd.nist.gov/vuln/detail/${cveId}`;
        document.getElementById('btn-exploit-db-link').href = `https://www.exploit-db.com/?q=${cveId}`;
        
        cveModal.classList.add('active');
    }

    btnCloseModal.addEventListener('click', () => cveModal.classList.remove('active'));
    btnCloseTelegramModal.addEventListener('click', () => telegramModal.classList.remove('active'));
    
    window.addEventListener('click', (e) => {
        if (e.target === cveModal) cveModal.classList.remove('active');
        if (e.target === telegramModal) telegramModal.classList.remove('active');
    });

    // ===== TELEGRAM NOTIFICATION =====
    btnTelegramNotify.addEventListener('click', () => {
        telegramModal.classList.add('active');
    });

    // ===== EXPORT REPORT =====
    btnExportReport.addEventListener('click', () => {
        document.body.setAttribute('data-date', new Date().toLocaleString('it-IT'));
        window.print();
    });

    // ===== SKELETONS =====
    function showSkeletons() {
        threatCardsContainer.innerHTML = Array(6).fill(0).map(() => `
            <div class="skeleton-card skeleton"></div>
        `).join('');
        
        document.getElementById('hn-news-container').innerHTML = Array(3).fill(0).map(() => `
            <div class="skeleton" style="height: 80px; margin-bottom: 1rem; border-radius: 0.5rem;"></div>
        `).join('');
        
        document.getElementById('reddit-news-container').innerHTML = Array(3).fill(0).map(() => `
            <div class="skeleton" style="height: 80px; margin-bottom: 1rem; border-radius: 0.5rem;"></div>
        `).join('');
    }

    // ===== FETCH DATA =====
    async function fetchData() {
        showSkeletons();
        try {
            const threatsResponse = await fetch('data/threats.json');
            threatsData = await threatsResponse.json();
            
            const newsResponse = await fetch('data/news.json');
            newsData = await newsResponse.json();

            if (threatsData.last_updated) {
                const date = new Date(threatsData.last_updated);
                lastUpdatedTime.textContent = date.toLocaleString('it-IT');
            }

            // Simulate slight delay for skeleton visibility
            setTimeout(() => {
                updateDashboard();
            }, 800);
        } catch (error) {
            console.error('Errore nel caricamento dei dati:', error);
            threatCardsContainer.innerHTML = '<p class="error">Dati non ancora disponibili. Attendi il primo aggiornamento automatico.</p>';
        }
    }

    // ===== WATCHLIST LOGIC =====
    function toggleWatchlist(cveId) {
        const index = watchlist.indexOf(cveId);
        if (index === -1) {
            watchlist.push(cveId);
        } else {
            watchlist.splice(index, 1);
        }
        localStorage.setItem('threatWatchlist', JSON.stringify(watchlist));
        renderThreats();
        renderWatchlist();
    }
    window.toggleWatchlist = toggleWatchlist;

    function renderWatchlist() {
        if (!watchlistContainer) return;
        watchlistContainer.innerHTML = '';
        
        const watchlistedItems = threatsData.nvd_cves.filter(item => watchlist.includes(item.cve.id));
        
        if (watchlistedItems.length === 0) {
            watchlistContainer.innerHTML = '<p class="error" style="grid-column: 1/-1;">La tua watchlist è vuota. Clicca sulla stella delle CVE per aggiungerle qui.</p>';
            return;
        }

        watchlistedItems.forEach((item, index) => {
            const card = createCveCard(item, index);
            watchlistContainer.appendChild(card);
        });
    }

    // Helper to create card (to avoid duplication)
    function createCveCard(item, index) {
        const cve = item.cve;
        const metrics = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
        const score = metrics?.baseScore || 'N/A';
        const severity = metrics?.baseSeverity || 'UNKNOWN';
        const description = cve.descriptions.find(d => d.lang === 'en')?.value || 'Nessuna descrizione disponibile.';
        const severityClass = getCardSeverityClass(score);
        const isWatchlisted = watchlist.includes(cve.id);
        
        const tech = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria || '';
        const vendor = tech.split(':')[3] || 'General';
        const product = tech.split(':')[4] || 'General';
        const epss = cve.epss || null;

        const card = document.createElement('div');
        card.className = `card ${severityClass}`;
        card.style.animationDelay = `${index * 50}ms`;
        card.innerHTML = `
            <div class="card-header">
                <span class="cve-id">${cve.id}</span>
                <div class="card-actions">
                    <button class="btn-star ${isWatchlisted ? 'active' : ''}" title="${isWatchlisted ? 'Rimuovi dalla Watchlist' : 'Aggiungi alla Watchlist'}" onclick="toggleWatchlist('${cve.id}')">
                        <i class="${isWatchlisted ? 'fas' : 'far'} fa-star"></i>
                    </button>
                    <button class="btn-copy" title="Copia CVE ID" onclick="navigator.clipboard.writeText('${cve.id}')">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
            </div>
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <div style="display: flex; align-items: center; gap: 1rem;">
                    <div class="cvss-gauge" data-score="${score}"></div>
                    <span class="badge ${getSeverityBadgeClass(score)}">${score} ${severity}</span>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 0.8rem; font-weight: bold; color: var(--primary-blue);">${vendor.toUpperCase()}</div>
                    <div style="font-size: 0.7rem; color: var(--text-secondary);">${product}</div>
                </div>
            </div>
            ${epss ? `
            <div class="epss-metric" title="Exploit Prediction Scoring System: probabilità di sfruttamento nel mondo reale">
                <span class="epss-label">Probabilità Exploit (EPSS):</span>
                <span class="epss-value">${(parseFloat(epss.epss) * 100).toFixed(2)}%</span>
                <div class="epss-bar-bg"><div class="epss-bar-fill" style="width: ${parseFloat(epss.epss) * 100}%"></div></div>
            </div>
            ` : ''}
            <div class="tech-tags">
                ${cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.slice(0, 3).map(c => `<span class="tag">${c.criteria.split(':')[4] || 'General'}</span>`).join('') || '<span class="tag">General</span>'}
            </div>
            <p class="description">${description}</p>
            <a href="#" class="source-link" onclick="event.preventDefault(); openCveModal(${JSON.stringify(item).replace(/"/g, '&quot;')})">
                Dettagli Completi <i class="fas fa-arrow-right"></i>
            </a>
        `;
        return card;
    }

    // ===== SEVERITY BADGE CLASS =====
    function getSeverityBadgeClass(score) {
        if (score >= 9.0) return 'badge-critical';
        if (score >= 7.0) return 'badge-high';
        if (score >= 4.0) return 'badge-medium';
        return 'badge-low';
    }

    function getCardSeverityClass(score) {
        if (score >= 9.0) return 'critical';
        if (score >= 7.0) return 'high';
        if (score >= 4.0) return 'medium';
        return 'low';
    }

    // ===== RENDER THREATS =====
    function renderThreats() {
        if (!threatCardsContainer) return;
        threatCardsContainer.innerHTML = '';
        const minSeverity = parseFloat(severityFilter.value);
        const searchTerm = techSearch.value.toLowerCase();
        const selectedSource = sourceFilter.value;
        const selectedVector = vectorFilter.value;

        console.log(`Rendering threats with filters: Score >= ${minSeverity}, Search: "${searchTerm}", Vector: ${selectedVector}`);

        const filteredCves = threatsData.nvd_cves.filter(item => {
            const cve = item.cve;
            const metrics = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData || cve.metrics?.cvssMetricV2?.[0]?.cvssData;
            const score = metrics?.baseScore || 0;
            const vector = metrics?.vectorString || '';
            const description = cve.descriptions.find(d => d.lang === 'en')?.value || '';
            const tech = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria || '';
            const vendor = tech.split(':')[3] || '';
            const product = tech.split(':')[4] || '';

            const matchesSeverity = score >= minSeverity;
            const matchesVector = selectedVector === 'all' || vector.includes(`AV:${selectedVector.charAt(0)}`);
            const matchesSearch = 
                description.toLowerCase().includes(searchTerm) || 
                tech.toLowerCase().includes(searchTerm) || 
                cve.id.toLowerCase().includes(searchTerm) ||
                vendor.toLowerCase().includes(searchTerm) ||
                product.toLowerCase().includes(searchTerm);
            
            const matchesSource = selectedSource === 'all' || selectedSource === 'nvd';

            return matchesSeverity && matchesVector && matchesSearch && matchesSource;
        });

        console.log(`Found ${filteredCves.length} CVEs matching filters out of ${threatsData.nvd_cves.length} total.`);

        filteredCves.forEach((item, index) => {
            const card = createCveCard(item, index);
            threatCardsContainer.appendChild(card);
        });

        if (filteredCves.length === 0) {
            const noResultsMsg = threatsData.nvd_cves.length === 0 
                ? 'Nessun dato caricato. Prova ad aggiornare i dati.' 
                : 'Nessuna minaccia trovata con i filtri attuali. Prova ad abbassare la severità minima.';
            threatCardsContainer.innerHTML = `<p class="error" style="grid-column: 1/-1; text-align: center; padding: 2rem;">${noResultsMsg}</p>`;
        }
    }

    // Make openCveModal global
    window.openCveModal = openCveModal;

    // ===== RENDER NEWS =====
    function renderNews() {
        const hnContainer = document.getElementById('hn-news-container');
        const redditContainer = document.getElementById('reddit-news-container');

        hnContainer.innerHTML = newsData.hacker_news.map((story, index) => `
            <div class="news-item" style="animation-delay: ${index * 50}ms;">
                <h4><a href="${story.url}" target="_blank">${story.title}</a></h4>
                <div class="news-meta">⭐ ${story.score} | by ${story.by} | ${new Date(story.time).toLocaleDateString('it-IT')}</div>
            </div>
        `).join('');

        redditContainer.innerHTML = newsData.reddit_netsec.map((post, index) => `
            <div class="news-item" style="animation-delay: ${index * 50}ms;">
                <h4><a href="${post.url}" target="_blank">${post.title}</a></h4>
                <div class="news-meta">⭐ ${post.score} | u/${post.author} | ${new Date(post.created_utc).toLocaleDateString('it-IT')}</div>
            </div>
        `).join('');
    }

    // ===== RENDER KEV SPOTLIGHT =====
    function renderKevSpotlight() {
        const kevContainer = document.getElementById('kev-spotlight-container');
        kevContainer.innerHTML = '';

        const recentKev = threatsData.cisa_kev.slice(0, 6);

        recentKev.forEach((vuln, index) => {
            const deadline = new Date(vuln.dueDate);
            const now = new Date();
            const diffDays = Math.ceil((deadline - now) / (1000 * 60 * 60 * 24));
            
            const card = document.createElement('div');
            card.className = 'card critical';
            card.style.animationDelay = `${index * 50}ms`;
            card.onclick = () => openCveModal(vuln);
            card.innerHTML = `
                <div class="card-header">
                    <span class="cve-id">${vuln.cveID}</span>
                    <span class="badge badge-critical" style="cursor: pointer;">ACTIVE EXPLOIT</span>
                </div>
                <div class="tech-tags">
                    <span class="tag">${vuln.vendorProject}</span>
                    <span class="tag">${vuln.product}</span>
                </div>
                <p class="description">${vuln.shortDescription}</p>
                <div class="affected-versions" style="color: var(--critical); font-weight: bold;">
                    ⏰ Patch Deadline: ${vuln.dueDate} (${diffDays > 0 ? diffDays + ' giorni rimasti' : '🔴 SCADUTA'})
                </div>
                <div style="margin-top: auto; display: flex; justify-content: space-between; align-items: center;">
                    <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" class="source-link" onclick="event.stopPropagation()">CISA KEV Catalog <i class="fas fa-external-link-alt"></i></a>
                    <span class="source-link">Dettagli <i class="fas fa-arrow-right"></i></span>
                </div>
            `;
            kevContainer.appendChild(card);
        });
    }

    // ===== UPDATE STATS =====
    function updateStats() {
        const criticalToday = threatsData.nvd_cves.filter(item => {
            const metrics = item.cve.metrics?.cvssMetricV31?.[0]?.cvssData || item.cve.metrics?.cvssMetricV30?.[0]?.cvssData;
            return (metrics?.baseScore || 0) >= 9.0;
        }).length;

        animateCounter('critical-cves-count', criticalToday);
        animateCounter('cisa-kev-count', threatsData.cisa_kev.length);
        
        // Calculate threat score (0-100)
        const highCount = threatsData.nvd_cves.filter(item => {
            const metrics = item.cve.metrics?.cvssMetricV31?.[0]?.cvssData || item.cve.metrics?.cvssMetricV30?.[0]?.cvssData;
            const score = metrics?.baseScore || 0;
            return score >= 7.0 && score < 9.0;
        }).length;

        const threatScore = Math.min(100, (criticalToday * 30) + (highCount * 15) + (threatsData.cisa_kev.length * 20));
        animateCounter('threat-score', Math.round(threatScore));
        
        // Tech most targeted
        const techCounts = {};
        threatsData.nvd_cves.forEach(item => {
            const tech = item.cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria?.split(':')[4];
            if (tech) techCounts[tech] = (techCounts[tech] || 0) + 1;
        });
        const sorted = Object.entries(techCounts).sort((a, b) => b[1] - a[1]);
        const topTech = sorted[0]?.[0] || 'N/A';
        const secondTech = sorted[1]?.[0] || '-';
        
        document.getElementById('top-targeted-tech').textContent = topTech;
        document.getElementById('second-targeted-tech').textContent = secondTech ? `2º: ${secondTech}` : '';

        // KEV deadline warning
        const kevSoon = threatsData.cisa_kev.filter(v => {
            const deadline = new Date(v.dueDate);
            const now = new Date();
            const diffDays = Math.ceil((deadline - now) / (1000 * 60 * 60 * 24));
            return diffDays > 0 && diffDays <= 7;
        }).length;
        
        if (kevSoon > 0) {
            document.getElementById('kev-deadline-warning').textContent = `🔴 ${kevSoon} scadono entro 7 giorni`;
        }

        // Create mini charts
        createMiniCharts();
        createTimelineChart();
        createVendorMatrix();
    }

    // ===== ANIMATE COUNTER =====
    function animateCounter(elementId, targetValue) {
        const element = document.getElementById(elementId);
        let currentValue = 0;
        const increment = Math.ceil(targetValue / 30);
        
        const interval = setInterval(() => {
            currentValue += increment;
            if (currentValue >= targetValue) {
                element.textContent = targetValue;
                clearInterval(interval);
            } else {
                element.textContent = currentValue;
            }
        }, 30);
    }

    // ===== MINI CHARTS =====
    function createMiniCharts() {
        const ctx = document.getElementById('miniChartCritical');
        if (!ctx) return;

        // Count critical CVEs from current data
        const criticalCount = threatsData.nvd_cves.filter(item => {
            const metrics = item.cve.metrics?.cvssMetricV31?.[0]?.cvssData || item.cve.metrics?.cvssMetricV30?.[0]?.cvssData;
            return (metrics?.baseScore || 0) >= 9.0;
        }).length;

        // For demo, generate some historical data based on current count
        const data = [
            Math.max(0, criticalCount - 5),
            Math.max(0, criticalCount - 2),
            Math.max(0, criticalCount - 4),
            Math.max(0, criticalCount - 1),
            Math.max(0, criticalCount - 3),
            Math.max(0, criticalCount - 2),
            criticalCount
        ];
        
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['D-6', 'D-5', 'D-4', 'D-3', 'D-2', 'D-1', 'Oggi'],
                datasets: [{
                    label: 'CVE Critiche',
                    data: data,
                    borderColor: '#ff3b3b',
                    backgroundColor: 'rgba(255, 59, 59, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false }, tooltip: { enabled: false } },
                scales: {
                    x: { display: false },
                    y: { display: false, beginAtZero: true }
                }
            }
        });
    }

    // ===== TIMELINE CHART =====
    function createTimelineChart() {
        const ctx = document.getElementById('threatTimelineChart');
        if (!ctx) return;

        // In a real app, we'd group by date. Here we use current data to distribute across 14 days
        const labels = Array.from({length: 14}, (_, i) => {
            const d = new Date();
            d.setDate(d.getDate() - (13 - i));
            return d.toLocaleDateString('it-IT', {month: 'short', day: 'numeric'});
        });

        const criticalCves = threatsData.nvd_cves.filter(item => {
            const metrics = item.cve.metrics?.cvssMetricV31?.[0]?.cvssData || item.cve.metrics?.cvssMetricV30?.[0]?.cvssData;
            return (metrics?.baseScore || 0) >= 9.0;
        });

        const highCves = threatsData.nvd_cves.filter(item => {
            const metrics = item.cve.metrics?.cvssMetricV31?.[0]?.cvssData || item.cve.metrics?.cvssMetricV30?.[0]?.cvssData;
            const score = metrics?.baseScore || 0;
            return score >= 7.0 && score < 9.0;
        });

        const mediumCves = threatsData.nvd_cves.filter(item => {
            const metrics = item.cve.metrics?.cvssMetricV31?.[0]?.cvssData || item.cve.metrics?.cvssMetricV30?.[0]?.cvssData;
            const score = metrics?.baseScore || 0;
            return score >= 4.0 && score < 7.0;
        });

        // Distribute counts across the timeline (mock distribution based on real counts)
        const distribute = (count, length) => {
            const base = Math.floor(count / length);
            const extra = count % length;
            return Array.from({length}, (_, i) => base + (i < extra ? 1 : 0)).sort(() => Math.random() - 0.5);
        };

        const criticalData = distribute(criticalCves.length, 14);
        const highData = distribute(highCves.length, 14);
        const mediumData = distribute(mediumCves.length, 14);

        if (timelineChart) timelineChart.destroy();

        timelineChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Critical',
                        data: criticalData,
                        borderColor: '#ff3b3b',
                        backgroundColor: 'rgba(255, 59, 59, 0.1)',
                        borderWidth: 3,
                        fill: false,
                        tension: 0.4
                    },
                    {
                        label: 'High',
                        data: highData,
                        borderColor: '#ff7b00',
                        backgroundColor: 'rgba(255, 123, 0, 0.1)',
                        borderWidth: 3,
                        fill: false,
                        tension: 0.4
                    },
                    {
                        label: 'Medium',
                        data: mediumData,
                        borderColor: '#ffd600',
                        backgroundColor: 'rgba(255, 214, 0, 0.1)',
                        borderWidth: 3,
                        fill: false,
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { intersect: false, mode: 'index' },
                plugins: {
                    legend: { display: true, position: 'top', labels: { color: '#e8eaf0' } },
                    tooltip: { backgroundColor: '#0d1321', titleColor: '#fff', bodyColor: '#94a3b8', borderColor: '#1e2a45', borderWidth: 1 }
                },
                scales: {
                    y: { beginAtZero: true, grid: { color: 'rgba(148, 163, 184, 0.1)' }, ticks: { color: '#94a3b8' } },
                    x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
                }
            }
        });
    }

    // ===== VENDOR RISK MATRIX =====
    function createVendorMatrix() {
        const vendorGrid = document.getElementById('vendor-grid');
        vendorGrid.innerHTML = '';

        const techCounts = {};
        threatsData.nvd_cves.forEach(item => {
            const tech = item.cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria?.split(':')[4];
            if (tech) {
                const normalizedTech = tech.charAt(0).toUpperCase() + tech.slice(1);
                techCounts[normalizedTech] = (techCounts[normalizedTech] || 0) + 1;
            }
        });

        const sortedVendors = Object.entries(techCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 15);

        const maxCount = sortedVendors[0]?.[1] || 1;

        sortedVendors.forEach(([vendor, count]) => {
            const intensity = Math.max(0.2, count / maxCount);
            const color = `rgba(255, 59, 59, ${intensity})`;
            
            const cell = document.createElement('div');
            cell.className = 'vendor-cell';
            cell.style.backgroundColor = color;
            cell.title = `${vendor}: ${count} vulnerabilità (Clicca per filtrare)`;
            cell.innerHTML = `<span style="font-size: 0.7rem; text-align: center;">${vendor}</span>`;
            
            cell.onclick = () => {
                techSearch.value = vendor;
                updateFilterBadge();
                renderThreats();
                // Scroll to filters
                document.querySelector('.filter-bar').scrollIntoView({ behavior: 'smooth' });
            };
            
            vendorGrid.appendChild(cell);
        });
    }

    // ===== API STATUS =====
    function updateApiStatus() {
        const status = threatsData.api_status || { nvd: 'offline', cisa: 'offline', epss: 'offline' };
        
        Object.entries(status).forEach(([api, state]) => {
            const dot = document.getElementById(`status-${api}`);
            if (dot) {
                dot.className = `status-dot ${state}`;
                dot.title = `Status ${api.toUpperCase()}: ${state.toUpperCase()}`;
            }
        });
    }

    // ===== FILTER LOGIC =====
    function updateFilterBadge() {
        const isFiltered = severityFilter.value !== '7.0' || techSearch.value !== '' || sourceFilter.value !== 'all' || vectorFilter.value !== 'all';
        filterBadge.style.display = isFiltered ? 'flex' : 'none';
        
        let count = 0;
        if (severityFilter.value !== '7.0') count++;
        if (techSearch.value !== '') count++;
        if (sourceFilter.value !== 'all') count++;
        if (vectorFilter.value !== 'all') count++;
        filterBadge.textContent = count;
    }

    severityFilter.addEventListener('input', () => {
        severityValue.textContent = severityFilter.value;
        updateFilterBadge();
        renderThreats();
    });

    techSearch.addEventListener('input', () => {
        updateFilterBadge();
        renderThreats();
    });

    sourceFilter.addEventListener('change', () => {
        updateFilterBadge();
        renderThreats();
    });

    vectorFilter.addEventListener('change', () => {
        updateFilterBadge();
        renderThreats();
    });

    btnResetFilters.addEventListener('click', () => {
        severityFilter.value = '7.0';
        severityValue.textContent = '7.0';
        techSearch.value = '';
        sourceFilter.value = 'all';
        vectorFilter.value = 'all';
        updateFilterBadge();
        renderThreats();
    });

    // ===== UPDATE DASHBOARD =====
    function updateDashboard() {
        renderThreats();
        renderNews();
        renderKevSpotlight();
        renderWatchlist();
        updateStats();
        updateApiStatus();
        checkForLiveAttacks();
    }

    // ===== LIVE ATTACK DETECTION =====
    function checkForLiveAttacks() {
        const today = new Date();
        const oneDayAgo = new Date(today.getTime() - (24 * 60 * 60 * 1000));
        
        // Cerca CVE critiche pubblicate nelle ultime 24 ore
        const recentCritical = threatsData.nvd_cves.filter(item => {
            const metrics = item.cve.metrics?.cvssMetricV31?.[0]?.cvssData || item.cve.metrics?.cvssMetricV30?.[0]?.cvssData;
            const score = metrics?.baseScore || 0;
            const pubDate = new Date(item.cve.published);
            return score >= 9.0 && pubDate > oneDayAgo;
        });

        // Cerca news con parole chiave allarmanti nelle ultime 24 ore
        const urgentKeywords = ['zero-day', 'exploit', 'active', 'breach', 'ransomware'];
        const urgentNews = [
            ...newsData.hacker_news,
            ...newsData.reddit_netsec
        ].filter(news => {
            const title = news.title.toLowerCase();
            const newsDate = new Date(news.time || news.created_utc);
            return urgentKeywords.some(kw => title.includes(kw)) && newsDate > oneDayAgo;
        });

        if (recentCritical.length > 0 || urgentNews.length > 0) {
            showLiveAttackAlert(recentCritical.length, urgentNews.length);
        }
    }

    function showLiveAttackAlert(cveCount, newsCount) {
        const alertId = 'live-attack-alert';
        if (document.getElementById(alertId)) return;

        const alert = document.createElement('div');
        alert.id = alertId;
        alert.className = 'live-alert-banner';
        alert.innerHTML = `
            <div class="alert-content">
                <span class="alert-icon">🚨</span>
                <div class="alert-text">
                    <strong>ALLERTA ATTACCO IN CORSO:</strong> 
                    Rilevate ${cveCount} nuove CVE critiche e ${newsCount} segnalazioni urgenti nelle ultime 24h.
                </div>
                <button class="btn-close-alert" onclick="this.parentElement.parentElement.remove()">&times;</button>
            </div>
        `;
        document.body.prepend(alert);
    }

    // ===== LOAD DATA & INITIALIZE =====
    // Load data and save filters to localStorage
    fetchData();

    // Save filter state to localStorage
    window.addEventListener('beforeunload', () => {
        localStorage.setItem('threatDashboardFilters', JSON.stringify({
            severity: severityFilter.value,
            tech: techSearch.value,
            source: sourceFilter.value,
            vector: vectorFilter.value
        }));
    });

    // Load filter state from localStorage
    const savedFilters = JSON.parse(localStorage.getItem('threatDashboardFilters') || '{}');
    if (savedFilters.severity) {
        severityFilter.value = savedFilters.severity;
        severityValue.textContent = savedFilters.severity;
    }
    if (savedFilters.tech) techSearch.value = savedFilters.tech;
    if (savedFilters.source) sourceFilter.value = savedFilters.source;
    if (savedFilters.vector) vectorFilter.value = savedFilters.vector;
    updateFilterBadge();
});
