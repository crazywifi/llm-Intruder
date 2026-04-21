/* LLM-Intruder Dashboard — Alpine.js Application */

const API = '';   // same origin

function sentinelApp() {
  return {
    // ── navigation ──────────────────────────────────────────────────────────
    page: 'projects',
    breadcrumb: 'Projects',
    navItems: [
      { id: 'projects', label: 'Projects',     icon: 'fa-folder'         },
      { id: 'wizard',   label: 'New Run',       icon: 'fa-plus-circle'    },
      { id: 'monitor',  label: 'Active Runs',   icon: 'fa-satellite-dish' },
      { id: 'results',  label: 'Results',        icon: 'fa-chart-bar'     },
      { id: 'playground',label:'Playground',    icon: 'fa-flask'          },
    ],
    navigate(id) {
      this.page = id;
      const labels = { projects:'Projects', wizard:'New Run', monitor:'Active Runs',
        results:'Results', playground:'Playground', help:'Help', about:'About' };
      this.breadcrumb = labels[id] || id;
      if (id === 'results') { this.buildResultsData(); }
      if (id === 'monitor' && this.activeRun) {
        // Ensure currentRunId is always in sync so pause/stop/resume buttons work
        // even after page navigation or a browser refresh
        if (!this.currentRunId && this.activeRun.run_id) {
          this.currentRunId = this.activeRun.run_id;
        }
        this.scrollTerminal();
      }
    },

    // ── projects ─────────────────────────────────────────────────────────────
    projects: [],
    loadingProjects: false,
    showNewProject: false,
    newProjectName: '',
    newProjectDesc: '',
    selectedProject: null,

    async loadProjects() {
      this.loadingProjects = true;
      try {
        const r = await fetch(`${API}/api/projects`);
        this.projects = await r.json();
      } catch(e) { this.projects = []; }
      this.loadingProjects = false;
    },

    async createProject() {
      if (!this.newProjectName.trim()) return;
      const r = await fetch(`${API}/api/projects`, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ name: this.newProjectName, description: this.newProjectDesc })
      });
      const proj = await r.json();
      await this.loadProjects();
      this.showNewProject = false;
      this.newProjectName = '';
      this.newProjectDesc = '';
      this.wizard.project_id = proj.id;
      this.navigate('wizard');
    },

    openProject(proj) {
      this.selectedProject = proj;
      this.activeRun = null;   // clear so buildResultsData fetches latest run from API
      this.recentTrials = [];
      this.allTrials = [];
      this.approvalPending = null;
      this.inputPrompt = null;
      this.inputPromptValue = '';
      this.navigate('results');
    },

    // Resumable-runs loader removed with scheduled mode.
    async loadResumableRuns(_projectId) { return []; },

    startRunForProject(proj) {
      this.wizard.project_id = proj.id;
      this.navigate('wizard');
    },

    async deleteProject(proj) {
      if (!confirm(`Delete project "${proj.name}" and ALL its runs/reports?\n\nThis cannot be undone.`)) return;
      try {
        const r = await fetch(`${API}/api/projects/${proj.id}`, { method: 'DELETE' });
        if (r.ok || r.status === 204) {
          if (this.selectedProject && this.selectedProject.id === proj.id) this.selectedProject = null;
          await this.loadProjects();
        } else {
          alert('Delete failed: ' + r.status);
        }
      } catch(e) { alert('Delete failed: ' + e.message); }
    },

    slugify(s) {
      return s.replace(/[^a-zA-Z0-9_\-]/g, '_').slice(0, 64) || 'project';
    },

    formatDate(iso) {
      if (!iso) return '—';
      return new Date(iso).toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' });
    },

    // ── wizard ───────────────────────────────────────────────────────────────
    wizardStep: 1,
    wizardStepNames: ['Project','Target','Run Mode','LLMs','Payloads','Strategies','Profile','Review'],
    wizard: {
      project_id: '',
      run_mode: 'campaign',
      target: {
        target_type: 'web',
        detection_mode: 'auto',   // 'auto' = LLM/heuristic selectors; 'intruder' = Burp-style user-picked elements
        target_url: '',
        scopeText: '',
        scope: [],
        requires_login: false,
        session_template_path: null,
        headless: false,
        auth_type: 'none',
        auth_value: '',
        content_type: 'application/json',
        burp_body_template: '',                                       // populated from Burp multipart/form body
        response_extraction_path: '$.choices[0].message.content',    // JSONPath to extract model reply
        extra_headers: {},                                            // original Burp headers preserved
      },
      payloads: {
        catalogues: [],
        strategies: [],
        encoding_techniques: [],
        custom_payload_text: '',
      },
      engagement: {
        engagement_id: '',
        authorisation_confirmed: false,
        max_trials: 500,
        run_all_payloads: true,
        timeout_seconds: 30,
        stop_on_first_success: false,
        dry_run: false,
        seed: null,
        detection_llm: { provider: 'heuristic', model: null, api_key: null, base_url: null },
      },
      target_profile: {
        application_name: '',
        application_type: 'chatbot',
        domain: 'general',
        sensitivity_type: 'all',
        target_language: 'english',
        goal_keywords_text: '',
        sensitive_patterns_text: '',
        success_description: '',
        previous_attempts: '',
        known_defenses_text: '',
      },
      advanced: {
        hunt_mode: 'FULL',
        multi_turn: false,
        auto_adv_temperature: true,
        tomb_raider: true,
        burn_detection: true,
        defense_fingerprint: true,
        report_formats: ['markdown', 'html'],
        auto_chain: true,
        pool_concurrency: 4,
        max_retries: 3,
        evidence_dir: 'evidence',
        adversarial_text: '',
        tenant_a: 'TENANT_A',
        tenant_b: 'TENANT_B',
        boundary_types: '',
        skip_judge: false,
        inline_judge: true,
        judge_workers: 1,
        attacker_llm: { provider: 'heuristic', model: null, api_key: null, base_url: null },
        judge_llm:   { provider: 'auto',      model: null, api_key: null, base_url: null },
      }
    },

    runModes: [
      { id:'campaign',  label:'Campaign',     icon:'fa-list',         color:'#00c9a7', desc:'Fire every selected payload once. Collects all responses. Fast. No AI required. Great for coverage sweeps.' },
      { id:'hunt',      label:'Hunt',         icon:'fa-brain',        color:'#bc8cff', desc:'Adaptive attack loop. Uses Attacker AI to mutate and escalate payloads based on what is working. Includes TombRaider, AutoAdv, BurnDetection.' },
      // 'scheduled' mode removed: checkpoint/resume not reliable.
      { id:'pool',      label:'Pool Run',     icon:'fa-bolt',         color:'#e3b341', desc:'Concurrent async sessions — sends payloads in parallel. Fastest throughput. For APIs only.' },
      { id:'probe',     label:'Single Probe', icon:'fa-crosshairs',   color:'#e08b3e', desc:'Send exactly one custom payload and inspect the raw response. Good for manual verification.' },
      { id:'rag_test',  label:'RAG Test',     icon:'fa-database',     color:'#f85149', desc:'Generate adversarial RAG payloads and run boundary probes against retrieval-augmented systems.' },
    ],

    cloudModels: {
      claude:      ['claude-opus-4-6','claude-sonnet-4-6','claude-haiku-4-5-20251001'],
      openai:      ['gpt-4o','gpt-4o-mini','gpt-4-turbo','gpt-3.5-turbo'],
      gemini:      ['gemini-2.0-flash','gemini-2.0-flash-lite','gemini-1.5-pro'],
      openrouter:  [
        'meta-llama/llama-3.3-70b-instruct:free',
        'meta-llama/llama-3.2-3b-instruct:free',
        'google/gemma-3-4b-it:free',
        'mistralai/mistral-7b-instruct:free',
        'qwen/qwen-2.5-72b-instruct:free',
        'deepseek/deepseek-r1:free',
        'deepseek/deepseek-chat-v3-0324:free',
        'openai/gpt-4o',
        'openai/gpt-4o-mini',
        'anthropic/claude-3.5-haiku',
        'anthropic/claude-sonnet-4-5',
        'google/gemini-2.0-flash-001',
        'mistralai/mistral-large',
        'x-ai/grok-3-mini-beta',
      ],
      grok:        ['grok-3-mini-beta','grok-3-beta','grok-2-1212','grok-beta'],
    },

    get authPlaceholder() {
      const t = this.wizard.target.auth_type;
      if (t === 'bearer') return 'eyJhbGciOi...';
      if (t === 'api_key') return 'sk-abc123...';
      if (t === 'basic')   return 'username:password';
      return 'header-name: value';
    },

    wizardNext() {
      // Basic validation per step
      if (this.wizardStep === 1 && !this.wizard.project_id) { alert('Please select or create a project.'); return; }
      if (this.wizardStep === 2 && !this.wizard.target.target_url) { alert('Please enter the target URL.'); return; }
      this.wizardStep++;
      if (this.wizardStep === 5 && this.catalogues.length === 0) this.loadCatalogues();
    },

    async launchRun() {
      if (!this.wizard.engagement.authorisation_confirmed) return;
      // Build scope from text
      this.wizard.target.scope = this.wizard.target.scopeText
        .split('\n').map(s => s.trim()).filter(Boolean);
      // Build keyword / list arrays from comma-separated text fields
      this.wizard.target_profile.goal_keywords = this.wizard.target_profile.goal_keywords_text
        .split(',').map(s => s.trim()).filter(Boolean);
      this.wizard.target_profile.sensitive_patterns = this.wizard.target_profile.sensitive_patterns_text
        .split(',').map(s => s.trim()).filter(Boolean);
      this.wizard.target_profile.known_defenses = this.wizard.target_profile.known_defenses_text
        .split(',').map(s => s.trim()).filter(Boolean);

      // Build payload config — null = use ALL, [] = use NONE, list = use that subset.
      // The backend distinguishes these three explicit states to honour deselect-all.
      const payloadsCfg = {
        catalogues:          this.catalogueAll ? null : [...this.wizard.payloads.catalogues],
        strategies:          this.strategyAll  ? null : [...this.wizard.payloads.strategies],
        encoding_techniques: this.encodingAll  ? null : [...this.wizard.payloads.encoding_techniques],
        custom_payload_text: this.wizard.payloads.custom_payload_text,
      };

      const body = {
        project_id: this.wizard.project_id,
        run_mode: this.wizard.run_mode,
        target: this.wizard.target,
        payloads: payloadsCfg,
        engagement: this.wizard.engagement,
        target_profile: this.wizard.target_profile,
        advanced: this.wizard.advanced,
      };

      try {
        const r = await fetch(`${API}/api/runs`, {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify(body),
        });
        const data = await r.json();
        this.currentRunId = data.run_id;
        this.activeRun = {
          run_id: data.run_id,
          project_id: this.wizard.project_id,   // needed for Results API calls
          status: 'pending',
          attack_pct: 0, judge_pct: 0, report_pct: 0,
          completed_trials: 0,
          total_trials: this.wizard.engagement.run_all_payloads ? 0 : this.wizard.engagement.max_trials,
          success_count: 0, partial_count: 0, refusal_count: 0,
          current_temp: 0.9,
          run_mode: this.wizard.run_mode,
          stop_requested: false,
          skip_requested: false,
          pause_requested: false,
          resume_from_checkpoint: false,
          model_fingerprint_provider: null,
          model_fingerprint_family: null,
          model_fingerprint_version: null,
          model_fingerprint_confidence: null,
          model_fingerprint_display: null,
          model_fingerprint_custom: false,
          model_fingerprint_avg_ms: 0,
        };
        this.recentTrials = [];
        this.terminalLogs = [];
        this.approvalPending = null;
        this.outerhtmlPending = null;
        this.outerhtmlInput = '';
        this.outerhtmlResult = null;
        this.inputPrompt = null;
        this.inputPromptValue = '';
        this.connectWebSocket(data.run_id);
        this.navigate('monitor');
        this.wizardStep = 1;
      } catch(e) {
        alert('Failed to launch run: ' + e.message);
      }
    },

    getProjectName() {
      const p = this.projects.find(p => p.id === this.wizard.project_id);
      return p ? p.name : '(none selected)';
    },

    async recordSession() {
      if (!this.wizard.target.target_url) { alert('Enter target URL first.'); return; }
      const r = await fetch(`${API}/api/sessions/record?project_id=${this.wizard.project_id}&target_url=${encodeURIComponent(this.wizard.target.target_url)}`, { method:'POST' });
      const d = await r.json();
      if (d.status === 'started' || d.status === 'ok') {
        this.wizard.target.session_template_path = d.session_template;
        this.wizard.target.requires_login = true;
        // Subscribe to the recording's WS channel so the ENTER prompt
        // surfaces here as a modal instead of blocking on server stdin.
        if (d.session_id) {
          this.terminalLogs = this.terminalLogs || [];
          this.terminalLogs.push({ level: 'info',
            message: '[RECORDER] Browser opened — log in, then click "Press ENTER" in the panel above.' });
          this.connectWebSocket(d.session_id);
        }
      }
    },

    async loadExistingSession() {
      if (!this.wizard.project_id) {
        alert('Select or create a project first.');
        return;
      }
      try {
        const r = await fetch(`${API}/api/sessions/templates/${this.wizard.project_id}`);
        if (!r.ok) { alert('Failed to list session templates: HTTP ' + r.status); return; }
        const list = await r.json();
        if (!list || list.length === 0) {
          alert('No recorded session templates found in this project.\n\nClick "Record Login Session" first to capture one.');
          return;
        }
        // Build a numbered picker — avoids needing a full modal UI
        let prompt = 'Recorded session templates in this project:\n\n';
        list.forEach((t, i) => { prompt += `  ${i + 1}. ${t.name}\n     ${t.path}\n\n`; });
        prompt += `Enter a number 1-${list.length} to load, or Cancel to abort:`;
        const choice = window.prompt(prompt, '1');
        if (!choice) return;
        const idx = parseInt(choice, 10) - 1;
        if (isNaN(idx) || idx < 0 || idx >= list.length) {
          alert('Invalid choice.');
          return;
        }
        const picked = list[idx];
        this.wizard.target.session_template_path = picked.path;
        this.wizard.target.requires_login = true;

        // Validate it actually contains session data
        try {
          const vr = await fetch(`${API}/api/sessions/validate?template_path=${encodeURIComponent(picked.path)}`, { method: 'POST' });
          const vd = await vr.json();
          if (vd.valid) {
            alert(`Loaded session: ${picked.name}\nTarget: ${vd.target_url}\n\n(Auth state will be replayed during runs.)`);
            // If the recorded template has a target_url, and our wizard doesn't, use it.
            if (vd.target_url && !this.wizard.target.target_url) {
              this.wizard.target.target_url = vd.target_url;
            }
          } else {
            alert(`Loaded session: ${picked.name}\nWARNING: validation failed — ${vd.error || 'unknown error'}`);
          }
        } catch (ve) {
          // validation is best-effort — the path is loaded regardless
          console.warn('Session validate failed:', ve);
        }
      } catch (e) {
        alert('Failed to load existing session: ' + e.message);
      }
    },

    burpFileContent: '',
    burpParsed: false,

    // Content-type normalisation map (covers all common variants)
    _ctMap: {
      'application/json':                  'application/json',
      'application/x-www-form-urlencoded': 'application/x-www-form-urlencoded',
      'multipart/form-data':               'multipart/form-data',
      'application/graphql':               'application/graphql',
      'application/xml':                   'application/xml',
      'text/xml':                          'application/xml',
      'application/soap+xml':              'application/soap+xml',
      'text/plain':                        'text/plain',
      'text/html':                         'text/html',
      'application/octet-stream':          'application/octet-stream',
      'application/x-ndjson':              'application/x-ndjson',
    },

    _normaliseCT(raw) {
      const ct = raw.split(';')[0].trim().toLowerCase();
      if (this._ctMap[ct]) return this._ctMap[ct];
      if (ct.includes('json'))  return 'application/json';
      if (ct.includes('form'))  return 'application/x-www-form-urlencoded';
      if (ct.includes('xml'))   return 'application/xml';
      if (ct.includes('graph')) return 'application/graphql';
      return ct;
    },

    // Client-side Burp request parser — runs immediately on file load
    _parseBurpText(text) {
      // Split headers from body (blank line separator)
      const blankIdx = text.search(/\r?\n\r?\n/);
      const headerSection = blankIdx >= 0 ? text.slice(0, blankIdx) : text;
      const bodySection   = blankIdx >= 0 ? text.slice(blankIdx).replace(/^\r?\n\r?\n/, '') : '';

      const lines = headerSection.split(/\r?\n/);
      // Line 0: METHOD /path HTTP/1.x
      const reqLine = (lines[0] || '').trim();
      const reqParts = reqLine.split(' ');
      let path = '';
      if (reqParts.length >= 2) path = reqParts[1];

      let host = '', contentType = '', authHeader = '';
      const _dropHeaders = new Set([
        'host','content-length','transfer-encoding','connection',
        'keep-alive','upgrade','proxy-authenticate','proxy-authorization',
        'te','trailers',
      ]);
      const preservedHeaders = {};

      for (const line of lines.slice(1)) {  // skip request line
        if (!line.trim()) break;
        const colonIdx = line.indexOf(':');
        if (colonIdx < 0) continue;
        const name = line.slice(0, colonIdx).trim();
        const value = line.slice(colonIdx + 1).trim();
        const lc = name.toLowerCase();
        if (lc === 'host') {
          host = value;
        } else if (lc === 'content-type') {
          contentType = value;
        } else if (lc === 'authorization') {
          authHeader = value;
        } else if (!_dropHeaders.has(lc)) {
          preservedHeaders[name] = value;
        }
      }

      // Store preserved headers (server parse will override with its own collection)
      if (Object.keys(preservedHeaders).length > 0) {
        this.wizard.target.extra_headers = preservedHeaders;
      }

      // Build full URL
      const scheme = (host.includes('localhost') || host.match(/:\d+$/)) ? 'http' : 'https';
      const fullUrl = host ? `${scheme}://${host}${path}` : '';

      // Auto-set target URL (always overwrite when Burp imported)
      if (fullUrl) this.wizard.target.target_url = fullUrl;

      // Auto-set content type
      if (contentType) {
        this.wizard.target.content_type = this._normaliseCT(contentType);
      }

      // Auto-set auth
      if (authHeader) {
        const lower = authHeader.toLowerCase();
        if (lower.startsWith('bearer ')) {
          this.wizard.target.auth_type  = 'bearer';
          this.wizard.target.auth_value = authHeader.slice(7).trim();
        } else if (lower.startsWith('basic ')) {
          this.wizard.target.auth_type  = 'basic';
          try { this.wizard.target.auth_value = atob(authHeader.slice(6).trim()); } catch(e) {}
        } else if (lower.startsWith('apikey ') || lower.startsWith('api-key ')) {
          this.wizard.target.auth_type  = 'api_key';
          this.wizard.target.auth_value = authHeader.split(' ').slice(1).join(' ').trim();
        }
      }

      // ── Parse body for multipart / form-urlencoded → build burp_body_template ──
      const normCT = this._normaliseCT(contentType || '');
      if ((normCT === 'multipart/form-data' || normCT === 'application/x-www-form-urlencoded') && bodySection.trim()) {
        const template = this._buildBodyTemplate(contentType, bodySection);
        if (template) this.wizard.target.burp_body_template = template;
      } else {
        // For JSON bodies, try to detect and preserve the structure with ${PAYLOAD}
        if (bodySection.trim().startsWith('{')) {
          try {
            const parsed = JSON.parse(bodySection.trim());
            const tmpl = this._injectPayloadPlaceholder(parsed);
            if (tmpl) this.wizard.target.burp_body_template = tmpl;
          } catch(e) { /* not valid JSON, ignore */ }
        }
      }

      // ── Auto-detect response extraction path from URL ─────────────────────
      const ul = (fullUrl || '').toLowerCase();
      if (ul.includes('lakera') || ul.includes('gandalf')) {
        this.wizard.target.response_extraction_path = '$.answer';
      } else if (ul.includes('anthropic')) {
        this.wizard.target.response_extraction_path = '$.content[0].text';
      } else if (ul.includes('generativelanguage.googleapis') || ul.includes('gemini')) {
        this.wizard.target.response_extraction_path = '$.candidates[0].content.parts[0].text';
      } else if (ul.includes('huggingface')) {
        this.wizard.target.response_extraction_path = '$[0].generated_text';
      }
      // else keep the default OpenAI-compatible path

      this.burpParsed = true;
    },

    // Detect which field is the user-input / payload field and replace its value with ${PAYLOAD}
    _payloadFieldNames: new Set([
      'prompt','message','query','question','input','text','content','msg',
      'user_input','user_message','userInput','userMessage','q','ask','request'
    ]),

    _buildBodyTemplate(contentType, bodyText) {
      const ct = (contentType || '').toLowerCase();
      const fields = {};

      if (ct.includes('multipart')) {
        // RFC 2046: boundary marker in body = "--" + the boundary parameter value
        // IMPORTANT: match on original contentType (not lowercased ct) to preserve boundary case
        const bMatch = contentType.match(/boundary=([^\s;"]+)/i);
        if (!bMatch) return null;
        const boundary = '--' + bMatch[1];  // original case — body uses exact same boundary string
        // Plain string split — avoids regex escaping issues with complex boundary strings
        const parts = bodyText.split(boundary);
        for (const part of parts) {
          const stripped = part.trim();
          // Skip empty parts and the closing "--" delimiter part
          if (!stripped || stripped.startsWith('--')) continue;
          const cdMatch = part.match(/Content-Disposition:[^\r\n]*name="([^"]+)"/i);
          if (!cdMatch) continue;
          const name = cdMatch[1];
          // Value is after the blank line following the part headers
          const valueMatch = part.match(/\r?\n\r?\n([\s\S]*)/);
          const value = valueMatch ? valueMatch[1].replace(/\r?\n$/, '') : '';
          fields[name] = value;
        }
      } else if (ct.includes('form-urlencoded')) {
        // Parse URL-encoded body
        for (const pair of bodyText.split('&')) {
          const [k, v] = pair.split('=').map(decodeURIComponent);
          if (k) fields[k] = v || '';
        }
      }

      if (!Object.keys(fields).length) return null;

      // Find the payload field — prefer known names, fallback to last field
      let payloadField = null;
      for (const name of Object.keys(fields)) {
        if (this._payloadFieldNames.has(name.toLowerCase())) { payloadField = name; break; }
      }
      if (!payloadField) payloadField = Object.keys(fields)[Object.keys(fields).length - 1];

      // Build template JSON: non-payload fields keep their values, payload field → ${PAYLOAD}
      const tpl = {};
      for (const [k, v] of Object.entries(fields)) {
        tpl[k] = k === payloadField ? '${PAYLOAD}' : v;
      }
      return JSON.stringify(tpl);
    },

    // For JSON bodies — walk the object and replace the most likely "user message" value with ${PAYLOAD}
    _injectPayloadPlaceholder(obj, depth = 0) {
      if (depth > 5) return null;
      if (typeof obj !== 'object' || obj === null) return null;
      const clone = Array.isArray(obj) ? [...obj] : {...obj};
      for (const key of Object.keys(clone)) {
        const lk = key.toLowerCase();
        if (this._payloadFieldNames.has(lk) && typeof clone[key] === 'string') {
          clone[key] = '${PAYLOAD}';
          return JSON.stringify(clone);
        }
        if (typeof clone[key] === 'object') {
          const res = this._injectPayloadPlaceholder(clone[key], depth + 1);
          if (res !== null) {
            clone[key] = JSON.parse(res);
            return JSON.stringify(clone);
          }
        }
      }
      return null;
    },

    handleBurpFile(e) {
      const f = e.target.files[0];
      if (!f) return;
      const reader = new FileReader();
      reader.onload = ev => {
        this.burpFileContent = ev.target.result;
        // Client-side parse first (instant)
        this._parseBurpText(ev.target.result);
        // Server-side parse auto-triggered (collects all preserved headers etc.)
        this.parseBurp();
      };
      reader.readAsText(f);
    },

    async parseBurp() {
      if (!this.burpFileContent) return;
      // First apply client-side parse for instant fields
      this._parseBurpText(this.burpFileContent);
      // Then try server-side for deeper parsing (body template etc.)
      try {
        const r = await fetch(`${API}/api/burp-import`, {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ burp_text: this.burpFileContent }),
        });
        if (r.ok) {
          const d = await r.json();
          if (d.status === 'ok' && d.adapter) {
            const a = d.adapter;
            console.log('[Burp server-parse]', {
              url: a.url,
              content_type: a.content_type,
              burp_body_template: a.burp_body_template,
              response_extraction_path: a.response_extraction_path,
              extra_headers_count: a.extra_headers ? Object.keys(a.extra_headers).length : 0,
            });
            if (a.url)                      this.wizard.target.target_url               = a.url;
            if (a.auth_type)                this.wizard.target.auth_type                = a.auth_type;
            if (a.auth_value)               this.wizard.target.auth_value               = a.auth_value;
            if (a.content_type)             this.wizard.target.content_type             = this._normaliseCT(a.content_type);
            if (a.burp_body_template)       this.wizard.target.burp_body_template       = a.burp_body_template;
            if (a.response_extraction_path) this.wizard.target.response_extraction_path = a.response_extraction_path;
            if (a.extra_headers)            this.wizard.target.extra_headers            = a.extra_headers;
          }
        }
      } catch(e) { /* server not available — client parse already applied above */ }
    },

    // ── payloads / strategies ────────────────────────────────────────────────
    catalogues: [],
    strategies: [],
    encodings:  [],

    // Explicit selection mode flags — true means "ALL", false means use explicit array
    // Default: ALL selected for everything
    catalogueAll: true,
    strategyAll:  true,
    encodingAll:  true,

    // ── Catalogue sync from internet sources ──────────────────────────────
    syncingCatalogue: false,
    syncResult: null,

    async syncCatalogueFromInternet() {
      if (this.syncingCatalogue) return;
      this.syncingCatalogue = true;
      this.syncResult = null;
      try {
        const resp = await fetch(`${API}/api/payloads/sync-catalogue`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({}),
        });
        const data = await resp.json();
        this.syncResult = data;
        // Refresh the catalogue counts so users see newly-added payloads
        await this.loadCatalogues();
      } catch (err) {
        this.syncResult = { status: 'error', detail: String(err) };
      } finally {
        this.syncingCatalogue = false;
      }
    },

    async loadCatalogues() {
      try {
        const [c, s, e] = await Promise.all([
          fetch(`${API}/api/payloads/catalogues`).then(r=>r.json()),
          fetch(`${API}/api/payloads/strategies`).then(r=>r.json()),
          fetch(`${API}/api/payloads/encodings`).then(r=>r.json()),
        ]);
        this.catalogues = c;
        this.strategies = s;
        this.encodings  = e;
      } catch(err) { console.error('Failed to load payload data', err); }
    },

    // ── Catalogues ──
    get catalogueGroups() {
      return [...new Set(this.catalogues.map(c => c.group))];
    },
    getCataloguesByGroup(g) { return this.catalogues.filter(c => c.group === g); },

    isCatalogueSelected(name) {
      if (this.catalogueAll) return true;
      return this.wizard.payloads.catalogues.includes(name);
    },
    toggleCatalogue(name) {
      if (this.catalogueAll) {
        // Switch to explicit mode: all selected EXCEPT this one
        this.catalogueAll = false;
        this.wizard.payloads.catalogues = this.catalogues.map(c => c.name).filter(n => n !== name);
        return;
      }
      const idx = this.wizard.payloads.catalogues.indexOf(name);
      if (idx >= 0) {
        this.wizard.payloads.catalogues.splice(idx, 1);
      } else {
        this.wizard.payloads.catalogues.push(name);
        // If all are now manually selected, switch back to 'all' mode
        if (this.wizard.payloads.catalogues.length === this.catalogues.length) {
          this.catalogueAll = true;
          this.wizard.payloads.catalogues = [];
        }
      }
    },
    selectAllCatalogues() {
      this.catalogueAll = true;
      this.wizard.payloads.catalogues = [];
    },
    deselectAllCatalogues() {
      this.catalogueAll = false;
      this.wizard.payloads.catalogues = [];
    },

    // ── Strategies ──
    get strategyGroups() { return [...new Set(this.strategies.map(s => s.group))]; },
    getStrategiesByGroup(g) { return this.strategies.filter(s => s.group === g); },

    isStrategySelected(name) {
      if (this.strategyAll) return true;
      return this.wizard.payloads.strategies.includes(name);
    },
    toggleStrategy(name) {
      if (this.strategyAll) {
        this.strategyAll = false;
        this.wizard.payloads.strategies = this.strategies.map(s => s.name).filter(n => n !== name);
        return;
      }
      const idx = this.wizard.payloads.strategies.indexOf(name);
      if (idx >= 0) {
        this.wizard.payloads.strategies.splice(idx, 1);
      } else {
        this.wizard.payloads.strategies.push(name);
        if (this.wizard.payloads.strategies.length === this.strategies.length) {
          this.strategyAll = true;
          this.wizard.payloads.strategies = [];
        }
      }
    },
    selectAllStrategies() {
      this.strategyAll = true;
      this.wizard.payloads.strategies = [];
    },
    deselectAllStrategies() {
      this.strategyAll = false;
      this.wizard.payloads.strategies = [];
    },

    // ── Encodings ──
    isEncodingSelected(name) {
      if (this.encodingAll) return true;
      return this.wizard.payloads.encoding_techniques.includes(name);
    },
    toggleEncoding(name) {
      if (this.encodingAll) {
        this.encodingAll = false;
        this.wizard.payloads.encoding_techniques = this.encodings.map(e => e.name).filter(n => n !== name);
        return;
      }
      const idx = this.wizard.payloads.encoding_techniques.indexOf(name);
      if (idx >= 0) {
        this.wizard.payloads.encoding_techniques.splice(idx, 1);
      } else {
        this.wizard.payloads.encoding_techniques.push(name);
        if (this.wizard.payloads.encoding_techniques.length === this.encodings.length) {
          this.encodingAll = true;
          this.wizard.payloads.encoding_techniques = [];
        }
      }
    },
    selectAllEncodings() {
      this.encodingAll = true;
      this.wizard.payloads.encoding_techniques = [];
    },
    deselectAllEncodings() {
      this.encodingAll = false;
      this.wizard.payloads.encoding_techniques = [];
    },

    // ── Estimated trial count (live, shown in wizard Step 6 and review) ──────
    get estimatedPayloadCount() {
      if (this.catalogueAll) {
        return this.catalogues.reduce((s, c) => s + (c.count || 0), 0);
      }
      return this.catalogues
        .filter(c => this.wizard.payloads.catalogues.includes(c.name))
        .reduce((s, c) => s + (c.count || 0), 0);
    },

    get estimatedStrategyCount() {
      // passthrough is always Pass 0 — don't count it here
      if (this.strategyAll) {
        return this.strategies.filter(s => s.name !== 'passthrough').length;
      }
      return this.wizard.payloads.strategies.filter(s => s !== 'passthrough').length;
    },

    get estimatedEncodingCount() {
      if (this.encodingAll) return this.encodings.length;
      return this.wizard.payloads.encoding_techniques.length;
    },

    get estimatedTrialCount() {
      const n = this.estimatedPayloadCount;
      // Pass 0: plain × n, Pass 1: strategies × n, Pass 2: encodings × n
      return n * (1 + this.estimatedStrategyCount + this.estimatedEncodingCount);
    },

    get estimatedTrialLabel() {
      const n = this.estimatedPayloadCount;
      const s = this.estimatedStrategyCount;
      const e = this.estimatedEncodingCount;
      const t = this.estimatedTrialCount;
      return `${n} payloads × (1 plain + ${s} strategies + ${e} encodings) = ${t.toLocaleString()} trials`;
    },

    toggleReportFormat(fmt) {
      const arr = this.wizard.advanced.report_formats;
      const idx = arr.indexOf(fmt);
      if (idx >= 0) arr.splice(idx, 1); else arr.push(fmt);
    },

    // ── local LLMs ───────────────────────────────────────────────────────────
    localLLMs: { ollama_available:false, ollama_models:[], lmstudio_available:false, lmstudio_models:[] },
    async probeLocalLLMs() {
      try {
        const r = await fetch(`${API}/api/local-llms`);
        this.localLLMs = await r.json();
      } catch(e) { /* silently fail — server may be starting */ }
    },

    // ── active run / WebSocket ────────────────────────────────────────────────
    activeRun: null,
    currentRunId: null,
    activeRunCount: 0,
    recentTrials: [],
    terminalLogs: [],
    ws: null,
    _lastRunId: null,

    // Browser-test approval gate (web-app runs only)
    approvalPending: null,   // set to the approval_request payload while waiting for user confirm

    // Browser-test manual outerHTML gate
    outerhtmlPending: null,
    outerhtmlInput: '',
    outerhtmlResult: null,

    // Generic interactive-prompt gate (intruder setup wizard, login recorder, etc.)
    inputPrompt: null,
    inputPromptValue: '',

    // Confirmation modal state
    confirmModal: {
      show: false,
      title: '',
      message: '',
      btnLabel: 'Proceed',
      btnStyle: '',
      iconColor: 'color:#e3b341',
      onConfirm: () => {},
    },

    confirmAction(title, message, btnLabel, btnStyle, iconColor, action) {
      this.confirmModal = {
        show: true,
        title,
        message,
        btnLabel,
        btnStyle,
        iconColor,
        onConfirm: action,
      };
    },

    connectWebSocket(runId) {
      if (this.ws) { try { this.ws.close(); } catch(e) {} }
      // Track the active WS id so submitInputPrompt / stopRun / etc. can target it
      // (covers both real runs and session-recording sessions like rec-xxxx).
      this.currentRunId = runId;
      const proto = location.protocol === 'https:' ? 'wss' : 'ws';
      this.ws = new WebSocket(`${proto}://${location.host}/api/runs/ws/${runId}`);
      this.ws.onmessage = (e) => {
        let msg;
        try { msg = JSON.parse(e.data); } catch(err) { return; }
        if (msg.event === 'progress') {
          // Merge carefully — preserve http_status_counts which may have arrived earlier
          const prev = this.activeRun || {};
          const incoming = msg.data || {};
          const mergedCounts = Object.assign({}, prev.http_status_counts || {}, incoming.http_status_counts || {});
          this.activeRun = { ...prev, ...incoming, http_status_counts: mergedCounts };
          const activeStatuses = ['running', 'judging', 'reporting'];
          this.activeRunCount = activeStatuses.includes(this.activeRun.status) ? 1 : 0;
        } else if (msg.event === 'trial') {
          this.recentTrials.push(msg.data);
          if (this.recentTrials.length > 200) this.recentTrials.shift();
        } else if (msg.event === 'log') {
          this.terminalLogs.push(msg.data);
          if (this.terminalLogs.length > 500) this.terminalLogs.shift();
          this.$nextTick(() => this.scrollTerminal());
        } else if (msg.event === 'done') {
          const doneStatus = (msg.data && msg.data.status) || 'completed';
          this.activeRun = { ...this.activeRun, ...msg.data, status: doneStatus };
          this._lastRunId = this.activeRun.run_id;
          this.activeRunCount = 0;
          const doneLabel = doneStatus === 'stopped' ? '[STOPPED] Run was stopped by user.' : '[DONE] Run completed successfully.';
          this.terminalLogs.push({ level: doneStatus === 'stopped' ? 'warn' : 'success', message: doneLabel });
          this.$nextTick(() => this.scrollTerminal());
        } else if (msg.event === 'error') {
          if (this.activeRun) this.activeRun.status = 'failed';
          this.activeRunCount = 0;
          this.terminalLogs.push({ level:'error', message:'[ERROR] ' + (msg.data && msg.data.message || 'Unknown error') });
          this.$nextTick(() => this.scrollTerminal());
        } else if (msg.event === 'alert') {
          this.terminalLogs.push({ level:'warn', message:'[ALERT] ' + ((msg.data && msg.data.message) || 'Alert from server.') });
          this.$nextTick(() => this.scrollTerminal());
        } else if (msg.event === 'approval_request') {
          // Web-app run: SmartRecorder has detected selectors + fired a test probe.
          // Show the approval panel so the user can Accept or Reject.
          this.approvalPending = msg.data;
          this.terminalLogs.push({ level: 'warn', message: '[APPROVAL] Selector verification required — see the approval panel above the terminal.' });
          this.$nextTick(() => this.scrollTerminal());
        } else if (msg.event === 'approval_result') {
          // Server confirmed the approval decision was received; hide the panel.
          this.approvalPending = null;
        } else if (msg.event === 'outerhtml_request') {
          // Clear approval panel first, then show outerHTML panel on next tick
          // so Alpine re-renders cleanly without both panels fighting for DOM.
          this.approvalPending = null;
          this.outerhtmlResult = null;
          this.outerhtmlInput = '';
          // Small delay so the approval panel DOM removal completes before
          // the outerHTML panel insertion — prevents Alpine x-if race on Windows.
          setTimeout(() => {
            this.outerhtmlPending = msg.data;
            this.$nextTick(() => this.scrollTerminal());
          }, 150);
          this.terminalLogs.push({ level: 'warn', message: '[MANUAL] outerHTML input required — see the orange panel above the terminal.' });
          this.$nextTick(() => this.scrollTerminal());
        } else if (msg.event === 'outerhtml_result') {
          this.outerhtmlResult = msg.data;
          if (msg.data && msg.data.capture_ok) {
            this.terminalLogs.push({ level: 'success', message: '\u2713 [MANUAL] Selector confirmed — awaiting final approval.' });
          } else {
            this.terminalLogs.push({ level: 'warn', message: '\u26a0 [MANUAL] Selector not confirmed — text-diff fallback will be used.' });
          }
          this.$nextTick(() => this.scrollTerminal());
        } else if (msg.event === 'input_request') {
          // Server-side runner thread is blocked on input() — render the modal.
          this.inputPrompt = msg.data || null;
          this.inputPromptValue = '';
          this.terminalLogs.push({
            level: 'warn',
            message: '[PROMPT] Interactive input required — see the blue panel above the terminal.',
          });
          this.$nextTick(() => this.scrollTerminal());
        } else if (msg.event === 'input_result') {
          // Server acknowledged our submission — dismiss the modal.
          this.inputPrompt = null;
          this.inputPromptValue = '';
        }
      };
      this.ws.onerror = () => {
        this.terminalLogs.push({ level:'warn', message:'[WS] Connection error. Reconnecting...' });
      };
      this.ws.onclose = () => {
        // Reconnect if run is still in an active phase
        const activeStatuses = ['running', 'judging', 'reporting'];
        if (this.activeRun && activeStatuses.includes(this.activeRun.status)) {
          setTimeout(() => this.connectWebSocket(runId), 2000);
        }
      };
    },

    async stopRun() {
      const rid = this.currentRunId || (this.activeRun && this.activeRun.run_id);
      if (!rid) return;
      try {
        await fetch(`${API}/api/runs/${rid}/stop`, { method:'POST' });
      } catch(e) {}
      // Immediately reflect stop_requested so Stop button hides and Stopping... shows
      if (this.activeRun) {
        this.activeRun.stop_requested = true;
        this.activeRun.pause_requested = false;
        this.activeRun.skip_requested = false;
      }
      this.terminalLogs.push({ level:'warn', message:'[STOP] Stop requested — waiting for current trial to finish...' });
      this.$nextTick(() => this.scrollTerminal());
    },

    async skipRun() {
      const rid = this.currentRunId || (this.activeRun && this.activeRun.run_id);
      if (!rid) return;
      try {
        await fetch(`${API}/api/runs/${rid}/skip`, { method:'POST' });
      } catch(e) {}
      const phase = (this.activeRun && this.activeRun.status) || 'current';
      // Reflect skip in local state so Skip button hides immediately
      if (this.activeRun) {
        this.activeRun.skip_requested = true;
      }
      this.terminalLogs.push({ level:'warn', message:`[SKIP] Skipping ${phase} phase. Moving to next phase...` });
      this.$nextTick(() => this.scrollTerminal());
    },

    async pauseRun() {
      const rid = this.currentRunId || (this.activeRun && this.activeRun.run_id);
      if (!rid) return;
      try {
        await fetch(`${API}/api/runs/${rid}/pause`, { method:'POST' });
      } catch(e) {}
      if (this.activeRun) this.activeRun.pause_requested = true;
      this.terminalLogs.push({ level:'warn', message:'[PAUSE] Run paused by user.' });
      this.$nextTick(() => this.scrollTerminal());
    },

    async resumeRun() {
      const rid = this.currentRunId || (this.activeRun && this.activeRun.run_id);
      if (!rid) return;
      try {
        await fetch(`${API}/api/runs/${rid}/resume`, { method:'POST' });
      } catch(e) {}
      if (this.activeRun) {
        this.activeRun.pause_requested = false;
        this.activeRun.stop_requested = false;
      }
      this.terminalLogs.push({ level:'info', message:'[RESUME] Run resumed.' });
      this.$nextTick(() => this.scrollTerminal());
    },

    // ── Live speed control (inter-trial delay) ──────────────────────────────
    // Debounced so dragging the slider doesn't flood the server.
    _speedTimer: null,
    async setTrialDelay(delay_s) {
      const rid = this.currentRunId || (this.activeRun && this.activeRun.run_id);
      if (!rid) return;
      if (this._speedTimer) clearTimeout(this._speedTimer);
      this._speedTimer = setTimeout(async () => {
        try {
          await fetch(`${API}/api/runs/${rid}/delay`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ delay_s })
          });
          this.terminalLogs.push({
            level: 'info',
            message: `[SPEED] Inter-trial delay set to ${delay_s.toFixed(1)}s.`
          });
          this.$nextTick(() => this.scrollTerminal());
        } catch(e) { /* network blip — UI value already updated optimistically */ }
      }, 250);
    },

    // ── Browser-test selector approval (web-app runs) ────────────────────────
    async approveRecording(accepted) {
      // accepted = true (Accept), false (Cancel Run), or "retry" (Try Different Element)
      const rid = this.currentRunId || (this.activeRun && this.activeRun.run_id);
      if (!rid) return;
      try {
        await fetch(`${API}/api/runs/${rid}/approve`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ accepted }),
        });
      } catch(e) {
        this.terminalLogs.push({ level:'error', message:'[APPROVAL] Failed to send decision: ' + e });
      }
      this.approvalPending = null;
      if (accepted === true) {
        this.terminalLogs.push({ level: 'success', message: '[APPROVAL] ✓ Accepted — starting automated payload testing...' });
      } else if (accepted === 'retry') {
        this.terminalLogs.push({ level: 'info', message: '[MANUAL] Retrying — please paste a different outerHTML element.' });
        // outerhtmlPending will be set again when server broadcasts outerhtml_request
      } else {
        this.terminalLogs.push({ level: 'warn', message: '[APPROVAL] ✗ Cancelled — run will be aborted.' });
      }
      this.$nextTick(() => this.scrollTerminal());
    },

    // ── Generic interactive-prompt submission (intruder setup, login recorder) ──
    async submitInputPrompt(value) {
      const rid = this.currentRunId || (this.activeRun && this.activeRun.run_id);
      if (!rid || !this.inputPrompt) return;
      const promptId = this.inputPrompt.prompt_id;
      const payload = { prompt_id: promptId, value: (value == null ? '' : String(value)) };
      // Optimistically clear the modal — server will also send input_result.
      const previewRaw = payload.value.replace(/\n/g, ' ');
      const preview = previewRaw.length > 120 ? previewRaw.slice(0, 120) + '…' : previewRaw;
      this.inputPrompt = null;
      this.inputPromptValue = '';
      try {
        const r = await fetch(`${API}/api/runs/${rid}/input_response`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!r.ok) {
          const err = await r.json().catch(() => ({ detail: 'Unknown error' }));
          this.terminalLogs.push({ level: 'error', message: '[PROMPT] Submit failed: ' + (err.detail || r.status) });
        } else {
          this.terminalLogs.push({ level: 'info', message: '[PROMPT] Submitted: ' + (preview || '(empty / ENTER)') });
        }
      } catch(e) {
        this.terminalLogs.push({ level: 'error', message: '[PROMPT] Submit failed: ' + e });
      }
      this.$nextTick(() => this.scrollTerminal());
    },

    // ── Manual outerHTML submission (web-app runs, manual mode) ────────────────
    async submitOuterHtml() {
      const rid = this.currentRunId || (this.activeRun && this.activeRun.run_id);
      if (!rid) return;
      const html = (this.outerhtmlInput || '').trim();
      if (!html) { await this.skipOuterHtml(); return; }
      try {
        const r = await fetch(`${API}/api/runs/${rid}/outer_html`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ outer_html: html }),
        });
        if (!r.ok) {
          const err = await r.json().catch(() => ({ detail: 'Unknown error' }));
          this.terminalLogs.push({ level: 'error', message: '[MANUAL] Submit failed: ' + (err.detail || r.status) });
          this.$nextTick(() => this.scrollTerminal());
          return;
        }
      } catch(e) {
        this.terminalLogs.push({ level: 'error', message: '[MANUAL] Submit failed: ' + e });
        this.$nextTick(() => this.scrollTerminal());
        return;
      }
      this.outerhtmlPending = null;
      this.outerhtmlInput = '';
      this.terminalLogs.push({ level: 'info', message: '[MANUAL] outerHTML submitted — re-verifying selector...' });
      this.$nextTick(() => this.scrollTerminal());
    },

    async skipOuterHtml() {
      const rid = this.currentRunId || (this.activeRun && this.activeRun.run_id);
      if (!rid) return;
      try {
        await fetch(`${API}/api/runs/${rid}/outer_html`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ outer_html: '' }),
        });
      } catch(e) {}
      this.outerhtmlPending = null;
      this.outerhtmlInput = '';
      this.outerhtmlResult = null;
      this.terminalLogs.push({ level: 'info', message: '[MANUAL] Skipped — using text-diff fallback.' });
      this.$nextTick(() => this.scrollTerminal());
    },

    // resumeScheduledRun removed with scheduled mode.

    scrollTerminal() {
      const el = document.getElementById('terminal-output');
      if (el) el.scrollTop = el.scrollHeight;
    },

    formatLogLine(log) {
      const lvl = log.level || 'neutral';
      const classes = {
        info:'t-info', success:'t-success', warn:'t-warn', error:'t-error',
        strategy:'t-strategy', partial:'t-partial', debug:'t-debug',
      };
      const cls = classes[lvl] || 't-neutral';
      const msg = (log.message || '').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      return `<span class="${cls}">${msg}</span>`;
    },

    formatETA(secs) {
      if (!secs) return '—';
      const m = Math.floor(secs / 60), s = secs % 60;
      return m > 0 ? `${m}m${s.toString().padStart(2,'0')}s` : `${s}s`;
    },

    statusBadgeStyle(status) {
      const styles = {
        running:   'background:rgba(0,201,167,0.1);color:#00c9a7;border:1px solid rgba(0,201,167,0.3)',
        judging:   'background:rgba(88,166,255,0.1);color:#58a6ff;border:1px solid rgba(88,166,255,0.3)',
        reporting: 'background:rgba(63,185,80,0.1);color:#3fb950;border:1px solid rgba(63,185,80,0.3)',
        completed: 'background:rgba(63,185,80,0.1);color:#3fb950;border:1px solid rgba(63,185,80,0.3)',
        failed:    'background:rgba(248,81,73,0.1);color:#f85149;border:1px solid rgba(248,81,73,0.3)',
        stopped:   'background:rgba(125,133,144,0.1);color:#7d8590;border:1px solid rgba(125,133,144,0.3)',
        pending:   'background:rgba(227,179,65,0.1);color:#e3b341;border:1px solid rgba(227,179,65,0.3)',
      };
      return styles[status] || styles.pending;
    },

    verdictColor(v) {
      if (!v) return 'color:#7d8590';
      v = v.toLowerCase();
      if (v.includes('success') || v === 'fail') return 'color:#3fb950;font-weight:600';
      if (v.includes('partial')) return 'color:#bc8cff';
      if (v.includes('soft'))    return 'color:#e3b341';
      if (v.includes('hard'))    return 'color:#f85149';
      if (v.includes('unclear')) return 'color:#7d8590';
      return 'color:#8b949e';
    },

    // ── results ───────────────────────────────────────────────────────────────
    resultsTab: 'summary',
    trialSearch: '',
    trialFilter: '',
    topStrategies: [],
    reportPreview: '',
    reportPath: '',
    allTrials: [],
    verdictChart: null,
    resultsLoading: false,

    get filteredTrials() {
      return this.allTrials.filter(t => {
        const s = this.trialSearch.toLowerCase();
        const matchSearch = !s || (t.strategy||'').toLowerCase().includes(s) || (t.payload_preview||'').toLowerCase().includes(s);
        const matchFilter = !this.trialFilter || (t.verdict||'').includes(this.trialFilter);
        return matchSearch && matchFilter;
      });
    },

    async buildResultsData() {
      // Resolve project_id and run_id from whatever context we have
      const pid = (this.activeRun && this.activeRun.project_id)
               || (this.selectedProject && this.selectedProject.id);
      let rid = (this.activeRun && this.activeRun.run_id) || this._lastRunId;

      if (!pid) {
        // Nothing selected — clear and show empty state
        this.allTrials = [];
        this.topStrategies = [];
        this.$nextTick(() => this.drawChart({}));
        return;
      }

      this.resultsLoading = true;

      // If we have a project but no run_id, find the latest run for the project
      if (!rid) {
        try {
          const runs = await (await fetch(`${API}/api/runs/${pid}`)).json();
          if (Array.isArray(runs) && runs.length > 0) {
            // Sort by started_at descending and pick the latest
            runs.sort((a, b) => (b.started_at || '').localeCompare(a.started_at || ''));
            const latest = runs[0];
            rid = latest.run_id;
            // Restore activeRun so Report tab can download too
            if (!this.activeRun && rid) {
              this.activeRun = { ...latest, project_id: pid };
              this.currentRunId = rid;
              this._lastRunId = rid;
            }
            // Also expose fingerprint from meta if present
            if (latest.model_fingerprint_display && this.activeRun) {
              this.activeRun.model_fingerprint_provider = latest.model_fingerprint_provider;
              this.activeRun.model_fingerprint_family = latest.model_fingerprint_family;
              this.activeRun.model_fingerprint_confidence = latest.model_fingerprint_confidence;
              this.activeRun.model_fingerprint_display = latest.model_fingerprint_display;
              this.activeRun.model_fingerprint_custom = latest.model_fingerprint_custom;
            }
          }
        } catch(e) { /* ignore */ }
      }

      // During a live run — prefer the in-memory recentTrials (they have live verdicts)
      // but also fetch from DB so we see all trials including those not yet in-memory
      if (this.recentTrials.length > 0 && this.activeRun &&
          ['running','judging','reporting'].includes(this.activeRun.status)) {
        this.allTrials = [...this.recentTrials];
        this._computeStrategyStats();
        const counts = {};
        for (const t of this.allTrials) {
          const v = t.verdict || 'pending';
          counts[v] = (counts[v]||0) + 1;
        }
        this.$nextTick(() => this.drawChart(counts));
        this.resultsLoading = false;
        return;
      }

      // Fetch from DB (post-run or after refresh)
      if (pid && rid) {
        try {
          const r = await fetch(`${API}/api/runs/${pid}/${rid}/trials`);
          if (r.ok) {
            const d = await r.json();
            this.allTrials = d.trials || [];
            this._computeStrategyStats();
            this.$nextTick(() => this.drawChart(d.verdict_counts || {}));
            this.resultsLoading = false;
            return;
          }
        } catch(e) { /* fall through */ }
      }

      // Fallback — compute from whatever allTrials we have
      const counts = {};
      for (const t of this.allTrials) {
        const v = t.verdict || 'pending';
        counts[v] = (counts[v]||0) + 1;
      }
      this._computeStrategyStats();
      this.$nextTick(() => this.drawChart(counts));
      this.resultsLoading = false;
    },

    _computeStrategyStats() {
      const stratScores = {};
      for (const t of this.allTrials) {
        const s = t.strategy || 'unknown';
        if (!stratScores[s]) stratScores[s] = { jailbreaks: 0, total: 0 };
        stratScores[s].total++;
        if (t.verdict === 'fail' || t.verdict === 'success') stratScores[s].jailbreaks++;
      }
      const total = this.allTrials.length || 1;
      this.topStrategies = Object.entries(stratScores)
        .sort((a,b) => b[1].jailbreaks - a[1].jailbreaks || b[1].total - a[1].total)
        .slice(0, 8)
        .map(([name, s]) => ({
          name,
          pct: Math.round(s.jailbreaks / total * 100),
          count: s.total,
          jailbreaks: s.jailbreaks,
        }));
    },

    async loadReportPreview() {
      const pid = (this.activeRun && this.activeRun.project_id) || (this.selectedProject && this.selectedProject.id);
      const rid = (this.activeRun && this.activeRun.run_id) || this._lastRunId;
      if (!pid || !rid) { this.reportPreview = ''; this.reportPath = ''; return; }
      try {
        // Load HTML version for iframe rendering
        const r = await fetch(`${API}/api/runs/${pid}/${rid}/report?fmt=html`);
        if (r.ok) {
          const d = await r.json();
          this.reportPreview = d.content || '';
          this.reportPath = d.path || '';
        } else {
          this.reportPreview = '';
          this.reportPath = '';
        }
      } catch(e) { this.reportPreview = ''; this.reportPath = ''; }
    },

    async downloadReport(fmt) {
      const pid = (this.activeRun && this.activeRun.project_id) || (this.selectedProject && this.selectedProject.id);
      const rid = (this.activeRun && this.activeRun.run_id) || this._lastRunId;
      if (!pid || !rid) { alert('No run selected.'); return; }
      try {
        const r = await fetch(`${API}/api/runs/${pid}/${rid}/report?fmt=${fmt}`);
        if (!r.ok) { alert('Report not available yet.'); return; }
        const d = await r.json();
        const ext = fmt === 'markdown' ? 'md' : fmt;
        const blob = new Blob([d.content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a'); a.href = url; a.download = `report.${ext}`; a.click();
        URL.revokeObjectURL(url);
      } catch(e) { alert('Download failed: ' + e.message); }
    },

    async openFileLocation() {
      if (!this.reportPath) { alert('Report path not available.'); return; }
      try {
        const r = await fetch(`${API}/api/open-folder`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: this.reportPath })
        });
        if (!r.ok) {
          const d = await r.json().catch(() => ({}));
          alert('Could not open folder: ' + (d.detail || 'Unknown error'));
        }
      } catch(e) { alert('Failed to open folder: ' + e.message); }
    },

    drawChart(counts) {
      const el = document.getElementById('verdictChart');
      if (!el) return;
      if (this.verdictChart) { this.verdictChart.destroy(); this.verdictChart = null; }
      const colors = {
        'success':'#3fb950','fail':'#3fb950','partial_leak':'#bc8cff','partial':'#bc8cff',
        'soft_refusal':'#e3b341','hard_refusal':'#f85149','unclear':'#7d8590','pending':'#484f58',
        'pass':'#58a6ff','error':'#f85149'
      };
      const labels = Object.keys(counts);
      const data   = Object.values(counts);
      const bg     = labels.map(l => colors[l] || '#58a6ff');
      if (labels.length === 0) return;
      this.verdictChart = new Chart(el, {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            data,
            backgroundColor: bg,
            borderRadius: 4,
            borderWidth: 0,
            barThickness: 28,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                label: ctx => ` ${ctx.parsed.y} trial${ctx.parsed.y !== 1 ? 's' : ''}`
              }
            }
          },
          scales: {
            x: {
              ticks: { color: '#8b949e', font: { size: 11 } },
              grid: { display: false },
              border: { color: '#21262d' }
            },
            y: {
              beginAtZero: true,
              ticks: { color: '#7d8590', font: { size: 10 }, stepSize: 1, precision: 0 },
              grid: { color: '#21262d' },
              border: { color: '#21262d' }
            }
          }
        }
      });
    },

    // ── playground ────────────────────────────────────────────────────────────
    playgroundInput: '',
    playgroundOutput: '',
    activeTechniques: [],
    pgApplied: [],

    pgGroups: [
      { label: 'Encoding',    techniques: [
        { name:'base64',          label:'Base64',         desc:'Standard Base64 encoding.' },
        { name:'rot13',           label:'ROT13',          desc:'ROT13 character rotation.' },
        { name:'rot47',           label:'ROT47',          desc:'Rotates all printable ASCII.' },
        { name:'url_encode',      label:'URL Encode',     desc:'URL percent-encoding.' },
        { name:'hex',             label:'Hex',            desc:'Hexadecimal encoding.' },
        { name:'binary',          label:'Binary',         desc:'Binary 0/1 encoding.' },
        { name:'morse',           label:'Morse Code',     desc:'Morse code translation.' },
        { name:'caesar_cipher',   label:'Caesar',         desc:'Caesar cipher (shift 13).' },
        { name:'atbash',          label:'Atbash',         desc:'Reverse alphabet cipher.' },
        { name:'vigenere',        label:'Vigenère',       desc:'Vigenère polyalphabetic cipher.' },
        { name:'rail_fence',      label:'Rail Fence',     desc:'Rail fence transposition cipher.' },
      ]},
      { label: 'Character Substitution', techniques: [
        { name:'homoglyph',       label:'Homoglyph',      desc:'Cyrillic/Greek lookalike substitution.' },
        { name:'zalgo',           label:'Zalgo',          desc:'Combining diacritic overlays.' },
        { name:'unicode_tags',    label:'Unicode Tags',   desc:'Invisible Unicode Tags block (U+E0000).' },
        { name:'unicode_escape',  label:'Unicode Escape', desc:'Python-style \\uXXXX escapes.' },
        { name:'html_entities',   label:'HTML Entities',  desc:'HTML entity encoding.' },
        { name:'leetspeak',       label:'Leet Speak',     desc:'1337 character substitution.' },
        { name:'reverse',         label:'Reverse',        desc:'Reverses the string.' },
      ]},
      { label: 'Obfuscation Mutators', techniques: [
        { name:'token_obfuscation',label:'Token Obfusc.',  desc:'Obfuscates individual tokens.' },
        { name:'anti_classifier', label:'Anti-Classifier', desc:'Semantic synonym substitution to evade filters.' },
        { name:'bijection',       label:'Bijection',       desc:'Custom in-context alphabet bijection.' },
        { name:'glitch_tokens',   label:'Glitch Tokens',   desc:'Adversarial glitch token injection.' },
        { name:'skeleton_key',    label:'Skeleton Key',    desc:'Microsoft 2024 prefix bypass.' },
      ]},
    ],

    toggleTechnique(name) {
      const idx = this.activeTechniques.indexOf(name);
      if (idx >= 0) this.activeTechniques.splice(idx, 1);
      else this.activeTechniques.push(name);
    },

    async applyMutation() {
      if (!this.playgroundInput || this.activeTechniques.length === 0) return;
      const body = {
        text: this.playgroundInput,
        techniques: this.activeTechniques,
      };
      try {
        const r = await fetch(`${API}/api/playground/mutate`, {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify(body),
        });
        if (r.ok) {
          const d = await r.json();
          this.playgroundOutput = d.result;
          this.pgApplied = d.applied;
        } else {
          // Fallback: apply simple client-side ROT13 so UI shows something
          this.playgroundOutput = this.clientSideTransform(this.playgroundInput, this.activeTechniques[0]);
          this.pgApplied = [this.activeTechniques[0] + ' (client-side)'];
        }
      } catch(e) {
        this.playgroundOutput = '[Server not running. Start with: redteam dashboard]';
      }
    },

    clientSideTransform(text, tech) {
      if (tech === 'base64') return btoa(unescape(encodeURIComponent(text)));
      if (tech === 'rot13')  return text.replace(/[a-zA-Z]/g, c => String.fromCharCode(c.charCodeAt(0) + (c.toLowerCase() < 'n' ? 13 : -13)));
      if (tech === 'reverse') return text.split('').reverse().join('');
      if (tech === 'hex')    return Array.from(text).map(c => c.charCodeAt(0).toString(16).padStart(2,'0')).join(' ');
      return btoa(text);  // default
    },

    copyOutput() {
      if (!this.playgroundOutput) return;
      navigator.clipboard.writeText(this.playgroundOutput);
    },

    sendToRun() {
      if (!this.playgroundOutput) return;
      this.wizard.payloads.custom_payload_text = this.playgroundOutput;
      this.navigate('wizard');
    },

    // ── help sections ─────────────────────────────────────────────────────────
    helpSections: [
      { title:'Getting Started — 5-minute quick start', icon:'fa-rocket', open:false, content:`
        <ol class="space-y-2 ml-4 list-decimal">
          <li>Create a <strong>Project</strong> from the Projects page (acts as an isolated workspace with its own DB and evidence folder).</li>
          <li>Click <strong>New Run</strong> and walk through the wizard: pick a run mode → configure the target → select payloads → set Attacker / Judge LLMs → launch.</li>
          <li>Watch live progress on the <strong>Active Runs</strong> page. Trials, verdicts, burn score, and current temperature stream in real time over WebSocket.</li>
          <li>When the run finishes, judging and report generation auto-chain. Open <strong>Results</strong> to view findings, successful bypasses, and the generated Markdown / HTML / JSON / SARIF reports.</li>
          <li>Use the <strong>Playground</strong> to iterate on a single payload — preview encoding / mutation output before sending it to a real target.</li>
        </ol>
        <p class="mt-3">All UI actions map 1:1 to a CLI command (see the "CLI Commands" section). You can freely mix headless CI runs with the dashboard.</p>
      `},
      { title:'Run Modes — Campaign, Hunt, Pool, Probe, RAG-Test', icon:'fa-diagram-project', open:false, content:`
        <ul class="space-y-2 ml-2">
          <li><strong style="color:#00c9a7">Campaign</strong> — Fires every selected payload once and collects responses. Fast, deterministic, does not require an Attacker LLM. Best for broad coverage sweeps at the start of an engagement.</li>
          <li><strong style="color:#bc8cff">Hunt</strong> — Adaptive loop. After each trial the response is scored, strategy weights update, and the next attack is sampled from the best-performing families. TombRaider, AutoAdv Temperature, Burn Detection, and Defense Fingerprint run here. Best for maximum bypass probability on a hardened target.</li>
          <li><strong style="color:#e3b341">Pool Run</strong> — Concurrent async pool — N workers each send payloads in parallel sessions. Highest throughput; use when the target rate-limits per-connection but not globally.</li>
          <li><strong style="color:#58a6ff">Probe</strong> — Single-shot. Sends exactly one payload (web or API) and shows the raw response. Use to validate target configuration before a large run.</li>
          <li><strong style="color:#f85149">RAG Test</strong> — Two-tenant adversarial boundary test. Injects adversarial content into tenant A's context and checks whether tenant B can retrieve it. Detects retrieval-layer isolation failures.</li>
        </ul>
      `},
      { title:'Target Types — Web (browser) vs API', icon:'fa-bullseye', open:false, content:`
        <p><strong style="color:#00c9a7">Web target</strong> drives a real Chromium browser via Playwright. Use for chat UIs, copilots, agent front-ends, and any app where the LLM is reached through a web form rather than a public API. Supports session replay for login-gated apps.</p>
        <p class="mt-2"><strong style="color:#58a6ff">API target</strong> sends raw HTTP requests. Supply either a JSON/XML body template directly, or paste a saved Burp Suite request and the <code style="color:#00c9a7">burp-import</code> parser auto-extracts URL, method, headers, body template, and the JSONPath to the assistant reply (default <code>$.choices[0].message.content</code>). Bearer / API-key / Basic auth is supported.</p>
      `},
      { title:'Detection Mode — Auto vs Intruder (web only)', icon:'fa-crosshairs', open:false, content:`
        <p><strong style="color:#00c9a7">Auto</strong> — LLM + heuristic auto-detection finds the input field and response bubble selectors on the target page. Works out of the box on most public chat UIs.</p>
        <p class="mt-2"><strong style="color:#bc8cff">Intruder</strong> — Burp Suite-style interactive picker. You click the input box and the response area yourself, in a live browser window. Use this on shadow-DOM components, cross-origin iframes, or any site where auto-detect fails.</p>
      `},
      { title:'Payload Catalogues — Tri-state selection', icon:'fa-layer-group', open:false, content:`
        <p class="mb-2">Tri-state semantics on the catalogue picker:</p>
        <ul class="space-y-1 ml-4 list-disc">
          <li><strong>Select All</strong> — use every catalogue shipped with the tool (default).</li>
          <li><strong>Subset</strong> — pick individual catalogues; only those payloads are loaded.</li>
          <li><strong>Deselect All</strong> — zero catalogue payloads; the run uses only your custom payload text (if any).</li>
        </ul>
        <p class="mt-3 mb-2">Catalogues are grouped by attack category. Highlights:</p>
        <ul class="space-y-1 ml-2">
          <li>🔴 <strong>mcp_tool_poisoning</strong> — MCP description injection, MPMA, rug-pull attacks</li>
          <li>🔴 <strong>web_app_llm_attacks</strong> — XSS via LLM, SSRF, SQLi, RCE, path traversal, IDOR, SSTI</li>
          <li>🔴 <strong>markdown_exfiltration</strong> — CVE-2025-32711 EchoLeak, Lethal Trifecta, auto-loading image exfil</li>
          <li>🔴 <strong>system_prompt_extraction</strong> — Extracts hidden system instructions</li>
          <li>🟠 <strong>behavioral_injection</strong> — Skeleton Key, instruction override, persona injection</li>
          <li>🟠 <strong>incremental_extraction</strong> — Demonstrate-by-example, completion challenge, Socratic drilling</li>
          <li>🟠 <strong>parseltongue_attacks</strong> — Homoglyph, Zalgo, Unicode Tags, binary, bijection</li>
          <li>🟡 <strong>reconstruction_attacks</strong>, <strong>encoding_bypass</strong>, <strong>agent_misuse</strong>, <strong>rag_injection</strong>, and ~40 more.</li>
        </ul>
        <p class="mt-2 text-xs" style="color:#7d8590">Run <code>llm-intruder fetch-payloads</code> to update catalogues from the community repository.</p>
      `},
      { title:'Mutation Strategies — Tri-state selection', icon:'fa-dna', open:false, content:`
        <p class="mb-2">Strategies control HOW a payload is transformed before sending. Tri-state:</p>
        <ul class="space-y-1 ml-4 list-disc">
          <li><strong>Select All</strong> — adaptive auto-selection from every strategy. Hunt mode learns which strategies work against this target.</li>
          <li><strong>Subset</strong> — constrain the search to the listed strategies.</li>
          <li><strong>Deselect All</strong> — passthrough only; payloads are sent unmodified.</li>
        </ul>
        <p class="mt-3 mb-2">Shipped strategies include:</p>
        <ul class="space-y-1 ml-2">
          <li><code style="color:#00c9a7">passthrough</code> — send as-is, no mutation</li>
          <li><code style="color:#00c9a7">paraphrase</code> — LLM-powered semantic rewrite</li>
          <li><code style="color:#00c9a7">crescendo</code> — multi-turn escalation from benign to target</li>
          <li><code style="color:#00c9a7">siren</code> — 6-step trust-building extraction (ZeroLeaks)</li>
          <li><code style="color:#00c9a7">echo_chamber</code> — 5-step meta-normalisation sequence</li>
          <li><code style="color:#00c9a7">skeleton_key</code> — Microsoft 2024 RLHF gap exploit</li>
          <li><code style="color:#00c9a7">encoding_bypass</code> — applies one of the encoding techniques below</li>
          <li><code style="color:#00c9a7">bijection</code> — in-context custom-alphabet teaching</li>
          <li><code style="color:#00c9a7">glitch_tokens</code> — SolidGoldMagikarp and other adversarial tokens</li>
          <li><code style="color:#00c9a7">roleplay_reframe</code>, <code style="color:#00c9a7">many_shot_context</code>, <code style="color:#00c9a7">topic_attack</code>, <code style="color:#00c9a7">anti_classifier</code>, and more.</li>
        </ul>
      `},
      { title:'Encoding Techniques — Tri-state selection', icon:'fa-shield-halved', open:false, content:`
        <p class="mb-2">Encodings obfuscate payloads to bypass input classifiers and string-match filters. Tri-state works the same as catalogues / strategies.</p>
        <ul class="space-y-1 ml-2">
          <li><code style="color:#00c9a7">base64</code>, <code style="color:#00c9a7">hex</code>, <code style="color:#00c9a7">rot13</code>, <code style="color:#00c9a7">reverse</code> — classic transforms</li>
          <li><code style="color:#00c9a7">homoglyph</code>, <code style="color:#00c9a7">zalgo</code>, <code style="color:#00c9a7">unicode_tags</code> — Unicode-level obfuscation</li>
          <li><code style="color:#00c9a7">bijection_shuffle</code>, <code style="color:#00c9a7">vigenere</code>, <code style="color:#00c9a7">rail_fence</code> — keyed ciphers (Vigenère key and rail count configurable in Playground)</li>
          <li><code style="color:#00c9a7">morse</code>, <code style="color:#00c9a7">binary</code>, <code style="color:#00c9a7">leetspeak</code>, <code style="color:#00c9a7">piglatin</code>, <code style="color:#00c9a7">anti_classifier</code> (1–3 level), and more — 20 total.</li>
        </ul>
        <p class="mt-2">Use the <strong>Playground</strong> to preview the encoded output of any text before committing it to a run.</p>
      `},
      { title:'Attacker LLM & Judge LLM — Provider config', icon:'fa-robot', open:false, content:`
        <p><strong>Attacker LLM</strong> powers generative strategies (paraphrase, crescendo, siren, echo_chamber, etc.). Without one, those strategies fall back to templates.</p>
        <p class="mt-2"><strong>Judge LLM</strong> scores each response as <em>success</em> / <em>partial</em> / <em>refusal</em>. Without one (or with the Heuristic judge), scoring uses regex + keyword heuristics only.</p>
        <p class="mt-3 mb-1"><strong>Supported providers</strong> — configurable per-run in the wizard:</p>
        <ul class="space-y-1 ml-4 list-disc">
          <li><strong>Ollama</strong> — local, free, runs on your machine. Point at <code>http://localhost:11434</code>.</li>
          <li><strong>LM Studio</strong> — local, OpenAI-compatible server on <code>http://localhost:1234/v1</code>.</li>
          <li><strong>OpenAI</strong> — GPT-4o, GPT-4o-mini, GPT-4-turbo. Requires API key.</li>
          <li><strong>Anthropic (Claude)</strong> — claude-sonnet, claude-haiku. Requires API key.</li>
          <li><strong>Google Gemini</strong> — gemini-2.0-flash, gemini-1.5-pro. Requires API key.</li>
          <li><strong>Grok (xAI)</strong> — grok-2, grok-beta. Requires API key.</li>
          <li><strong>OpenRouter</strong> — unified gateway to 100+ models. Requires API key.</li>
          <li><strong>Heuristic</strong> — no LLM; regex + keyword judge only.</li>
          <li><strong>Auto</strong> — picks the first available provider (prefers local).</li>
        </ul>
      `},
      { title:'Adaptive Intelligence — TombRaider, Burn, AutoAdv, Fingerprint', icon:'fa-brain', open:false, content:`
        <p>Four adaptive modules run during Hunt mode. Each has a toggle in the wizard's Advanced Options and can be disabled independently.</p>
        <p class="mt-3"><strong style="color:#f85149">TombRaider</strong> — Two-phase targeted exploit. Phase 1 (Inspector) fingerprints which safety system defends the target (Azure Prompt Shield, Llama Guard, Anthropic Constitutional AI, OpenAI Moderation, etc.). Phase 2 (Exploit) switches to payloads known to bypass that specific system. Activates after trial 3 once defense confidence ≥ 0.50.</p>
        <p class="mt-3"><strong style="color:#e08b3e">Burn Detection</strong> — Monitors responses for patterns that indicate the target has identified the attack (e.g. "I notice you're trying to jailbreak me"). When the burn score exceeds 0.80, the conversation context is reset and strategy is rotated to a different family.</p>
        <p class="mt-3"><strong style="color:#bc8cff">AutoAdv Temperature</strong> — Outcome-driven sampling-temperature scheduler for the Attacker LLM. Success lowers temperature (focus), failure raises it (explore). Plateau after 3 fails → +0.15 boost; 5 consecutive fails → full reset to 0.90. Range 0.30 – 1.00.</p>
        <p class="mt-3"><strong style="color:#00c9a7">Defense Fingerprint</strong> — Maintains a probabilistic profile of which defense system is active based on refusal patterns, moderation markers, and response timing. Feeds TombRaider and surfaces in the report's "Defense Detected" section.</p>
      `},
      { title:'Model Fingerprinting — Identifying the target model', icon:'fa-fingerprint', open:false, content:`
        <p>Before trials begin, the tool attempts to identify the underlying model. It runs in <strong>parallel</strong> with the main run so the trial counter is accurate from trial #1.</p>
        <ul class="mt-2 space-y-1 ml-4 list-disc">
          <li><strong>URL inference</strong> — if the target hostname is a known provider (chat.openai.com, claude.ai, etc.), the model family is inferred immediately.</li>
          <li><strong>Active probing</strong> — otherwise, a 3-probe identity suite is sent (identity_direct, creator_probe, model_version). The responses are parsed to extract model name, creator, and version.</li>
          <li>Results appear in the report's "Target Model" section and help TombRaider pick the right bypass family.</li>
        </ul>
      `},
      { title:'Session Recording — Testing login-required apps', icon:'fa-key', open:false, content:`
        <p>For web applications that require authentication:</p>
        <ol class="mt-2 space-y-1 ml-4 list-decimal">
          <li>In the wizard Step 2, enable <strong>Requires Login</strong>.</li>
          <li>Click <strong>Record Login Session</strong> — a Playwright browser opens.</li>
          <li>Log in manually as a real user. Navigate to the chat / prompt page.</li>
          <li>Close the browser — cookies, localStorage, and sessionStorage are saved as a YAML session template.</li>
          <li>All subsequent runs (campaign, hunt, probe, browser-test) replay the session automatically before sending each payload.</li>
          <li>If the session expires, click <strong>Re-record</strong> in the wizard or run <code style="color:#00c9a7">llm-intruder session record</code>.</li>
        </ol>
        <p class="mt-2">Inspect saved templates with <code style="color:#00c9a7">llm-intruder session list</code> and validate them with <code style="color:#00c9a7">llm-intruder session validate</code>.</p>
      `},
      { title:'Engagement Profile — Trials, workers, dry-run', icon:'fa-sliders', open:false, content:`
        <ul class="space-y-2 ml-2">
          <li><strong>Run all payloads</strong> (default ON) — every selected payload runs exactly once, which overrides the trial cap. Toggle off to use <em>Max Trials</em> instead.</li>
          <li><strong>Max Trials</strong> (1–10000) — hard cap on trial count when "Run all" is off. Hunt uses this as the adaptive loop length.</li>
          <li><strong>Timeout (seconds)</strong> — per-request timeout before a trial is marked as failed (5–300).</li>
          <li><strong>Workers</strong> — parallel attack workers. Pool-Run honours this directly (1–32). Most targets rate-limit; start at 1–4.</li>
          <li><strong>Stop on first success</strong> — abort the run as soon as one trial is scored as a bypass. Useful for quick triage.</li>
          <li><strong>Dry run</strong> — no network traffic; prints the full payload list and exits. Use to verify catalogue / strategy selection.</li>
          <li><strong>Seed</strong> — deterministic RNG for reproducible runs.</li>
        </ul>
      `},
      { title:'Reports — Formats and what they contain', icon:'fa-file-export', open:false, content:`
        <p class="mb-2">Reports auto-generate at the end of campaign / hunt / pool runs. Pick formats in Advanced Options.</p>
        <ul class="space-y-1 ml-2">
          <li><strong>Markdown (.md)</strong> — Human-readable findings grouped by severity, with Attack Narrative, target model, defenses detected, and full request / response evidence per finding.</li>
          <li><strong>HTML (.html)</strong> — Styled interactive report with severity badges, collapsible trial evidence, and export-ready layout.</li>
          <li><strong>JSON (.json)</strong> — Machine-readable structured findings. Use for dashboards, SIEM ingestion, or custom tooling.</li>
          <li><strong>SARIF (.sarif)</strong> — Static Analysis Results Interchange Format. Integrates with GitHub Advanced Security, VS Code, Azure DevOps.</li>
        </ul>
        <p class="mt-2 text-xs" style="color:#7d8590">Every finding row records the exact payload sent and the exact response received — the report is evidence-grade.</p>
      `},
      { title:'CLI Commands — Full reference', icon:'fa-terminal', open:false, content:`
        <p class="mb-2 text-xs" style="color:#7d8590">Entry-point is <code style="color:#00c9a7">llm-intruder</code>. Every wizard action maps to one of these:</p>
        <div class="font-mono text-xs space-y-1">
          <div><span style="color:#00c9a7">llm-intruder doctor</span> — Check that all dependencies are installed and report versions</div>
          <div><span style="color:#00c9a7">llm-intruder init</span> — Scaffold a new engagement workspace with template YAML files</div>
          <div><span style="color:#00c9a7">llm-intruder run</span> — Validate config, initialise DB, launch from a YAML engagement file</div>
          <div><span style="color:#00c9a7">llm-intruder campaign</span> — Multi-trial payload campaign (broad coverage sweep)</div>
          <div><span style="color:#00c9a7">llm-intruder hunt</span> — Adaptive intelligent hunt (TombRaider + AutoAdv + Burn)</div>
          <div><span style="color:#00c9a7">llm-intruder repl</span> — Interactive Hunt REPL — run trials one at a time and steer live</div>
          <div><span style="color:#00c9a7">llm-intruder pool-run</span> — Concurrent async worker pool (fastest throughput)</div>
          <div><span style="color:#00c9a7">llm-intruder probe</span> — Single browser probe</div>
          <div><span style="color:#00c9a7">llm-intruder probe-api</span> — Single API probe</div>
          <div><span style="color:#00c9a7">llm-intruder browser-test</span> — Smart browser record-and-replay test</div>
          <div><span style="color:#00c9a7">llm-intruder rag-test</span> — RAG cross-tenant boundary testing</div>
          <div><span style="color:#00c9a7">llm-intruder profile</span> — Crawl a target and auto-generate a target profile YAML</div>
          <div><span style="color:#00c9a7">llm-intruder judge</span> — Backfill LLM verdicts onto trials from a previous run</div>
          <div><span style="color:#00c9a7">llm-intruder analyze</span> — Standalone response risk analyzer (PII, injection, policy)</div>
          <div><span style="color:#00c9a7">llm-intruder report</span> — Export report from DB (Markdown / HTML / JSON / SARIF)</div>
          <div><span style="color:#00c9a7">llm-intruder benchmark</span> — Compute guardrail effectiveness metrics (FPR / FNR / F1)</div>
          <div><span style="color:#00c9a7">llm-intruder compare</span> — Compare two engagement runs side-by-side</div>
          <div><span style="color:#00c9a7">llm-intruder burp-import</span> — Parse a saved Burp Suite request into adapter YAML</div>
          <div><span style="color:#00c9a7">llm-intruder fetch-payloads</span> — Build a single payloads.yaml (optional --fetch to include internet)</div>
          <div><span style="color:#00c9a7">llm-intruder sync-catalogue</span> — Merge new internet payloads into the catalogue/ folder (dedup + new categories)</div>
          <div><span style="color:#00c9a7">llm-intruder session record</span> — Record a login session template</div>
          <div><span style="color:#00c9a7">llm-intruder session validate</span> — Validate a session template is still fresh</div>
          <div><span style="color:#00c9a7">llm-intruder session list</span> — List saved session templates</div>
          <div><span style="color:#00c9a7">llm-intruder dashboard</span> — Launch this web dashboard</div>
        </div>
        <p class="mt-3">Add <code style="color:#7d8590">--help</code> to any command for full options. Example: <code style="color:#00c9a7">llm-intruder hunt --help</code></p>
      `},
      { title:'Safety — Authorised Use Only', icon:'fa-triangle-exclamation', open:false, content:`
        <p>LLM-Intruder generates genuinely harmful payloads and real attack traffic. It is intended exclusively for:</p>
        <ul class="mt-2 space-y-1 ml-4 list-disc">
          <li>Security researchers testing their own systems.</li>
          <li>Penetration testers with explicit written authorisation from the target system owner.</li>
          <li>Red-team engagements governed by a documented rules-of-engagement (RoE).</li>
        </ul>
        <p class="mt-3">The wizard asks you to confirm authorisation before every run. Trials, payloads, and responses are stored in the project's local SQLite DB and never transmitted anywhere except to the target you specify. Use responsibly.</p>
      `},
    ],

    // ── init ─────────────────────────────────────────────────────────────────
    async init() {
      await Promise.all([
        this.loadProjects(),
        this.probeLocalLLMs(),
        this.loadCatalogues(),
      ]);
    },
  };
}
