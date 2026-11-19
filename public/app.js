(() => {
  'use strict';

  /** @type {any | null} */
  let latestReport = null;
  let latestExcludeFixtures = false;
  let activeStackFilter = 'all';
  let presets = { selfPath: '', fixturePath: '', envApiKeyConfigured: false };
  let excludeFixturesFlag = false;
  /** @type {Map<string, { score: number, findingIds: Set<string> }>} */
  const baselineHistory = new Map();

  const csrfMeta = document.querySelector('meta[name="longinus-csrf"]');
  const csrfToken = csrfMeta ? csrfMeta.getAttribute('content') || '' : '';

  const targetInput = /** @type {HTMLInputElement} */ (document.getElementById('target-path-input'));
  const modeSelect = /** @type {HTMLSelectElement} */ (document.getElementById('analysis-mode-select'));
  const apiKeyInput = /** @type {HTMLInputElement} */ (document.getElementById('api-key-input'));
  const statusBanner = /** @type {HTMLElement} */ (document.getElementById('status-banner'));
  const overallScoreEl = /** @type {HTMLElement} */ (document.getElementById('overall-score'));
  const repoMetaLine = /** @type {HTMLElement} */ (document.getElementById('repo-meta-line'));
  const executiveSummaryEl = /** @type {HTMLElement} */ (document.getElementById('executive-summary'));
  const telemetryStrip = /** @type {HTMLElement} */ (document.getElementById('telemetry-strip'));
  const engineBadge = /** @type {HTMLElement} */ (document.getElementById('engine-badge'));
  const stackGrid = /** @type {HTMLElement} */ (document.getElementById('stack-grid'));
  const trustMapContainer = /** @type {HTMLElement} */ (document.getElementById('trust-map-container'));
  const roadmapList = /** @type {HTMLElement} */ (document.getElementById('roadmap-list'));
  const strideTbody = /** @type {HTMLElement} */ (document.getElementById('stride-tbody'));
  const findingsTbody = /** @type {HTMLElement} */ (document.getElementById('findings-tbody'));
  const destructionCertTbody = /** @type {HTMLElement} */ (document.getElementById('destruction-cert-tbody'));
  const destructionCertBadge = /** @type {HTMLElement} */ (document.getElementById('destruction-cert-badge'));
  const portfolioSection = /** @type {HTMLElement} */ (document.getElementById('portfolio-section'));
  const portfolioKpis = /** @type {HTMLElement} */ (document.getElementById('portfolio-kpis'));
  const portfolioTbody = /** @type {HTMLElement} */ (document.getElementById('portfolio-tbody'));

  const dialog = /** @type {HTMLDialogElement} */ (document.getElementById('patch-dialog'));
  const dialogMetaKicker = /** @type {HTMLElement} */ (document.getElementById('dialog-meta-kicker'));
  const dialogTitle = /** @type {HTMLElement} */ (document.getElementById('patch-dialog-title'));
  const dialogLocation = /** @type {HTMLElement} */ (document.getElementById('dialog-location'));
  const dialogSnippet = /** @type {HTMLElement} */ (document.getElementById('dialog-snippet'));
  const dialogRootCause = /** @type {HTMLElement} */ (document.getElementById('dialog-root-cause'));
  const dialogPatch = /** @type {HTMLElement} */ (document.getElementById('dialog-patch'));
  const dialogVerify = /** @type {HTMLElement} */ (document.getElementById('dialog-verify'));
  const copyPatchBtn = /** @type {HTMLButtonElement} */ (document.getElementById('copy-patch-btn'));

  // Mandatory fallback for browsers without native <dialog closedby="any"> support (e.g. Safari)
  if (dialog && !('closedBy' in HTMLDialogElement.prototype)) {
    dialog.addEventListener('click', (event) => {
      if (event.target !== dialog) return;
      const rect = dialog.getBoundingClientRect();
      const isDialogContent =
        rect.top <= event.clientY &&
        event.clientY <= rect.top + rect.height &&
        rect.left <= event.clientX &&
        event.clientX <= rect.left + rect.width;
      if (isDialogContent) return;
      dialog.close();
    });
  }

  /**
   * Safe DOM helper — strictly avoids innerHTML to maintain Trusted Types invariance.
   * @param {string} tag
   * @param {string=} className
   * @param {string=} text
   */
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  /**
   * @param {HTMLElement} container
   */
  function clearChildren(container) {
    while (container.firstChild) {
      container.removeChild(container.firstChild);
    }
  }

  /**
   * @param {string} stack
   */
  function formatStackLabel(stack) {
    switch (stack) {
      case 'ts-web-api':
        return 'TS / Next / Node';
      case 'flutter-firebase':
        return 'Flutter / Firebase';
      case 'python-go-cloud':
        return 'Python / Go / Cloud';
      default:
        return 'Secrets & Supply Chain';
    }
  }

  /**
   * @param {string} severity
   */
  function severityBadgeClass(severity) {
    if (severity === 'critical' || severity === 'high') return 'pill pill-crimson';
    if (severity === 'medium') return 'pill pill-amber';
    return 'pill pill-blue';
  }

  /**
   * @param {string} msg
   * @param {boolean=} isError
   */
  function setStatus(msg, isError = false) {
    statusBanner.textContent = msg;
    statusBanner.className = isError ? 'status-banner error' : 'status-banner';
  }

  /**
   * @param {any} report
   */
  function renderReport(report) {
    latestReport = report;
    const isUnscoped =
      report.scannedFiles === 0 ||
      (Array.isArray(report.stackSummaries) &&
        report.stackSummaries.every((s) => !s.evaluated));

    overallScoreEl.textContent = isUnscoped ? 'N/A' : String(report.overallDefenseScore);
    overallScoreEl.className = isUnscoped
      ? 'score-numeral score-warn'
      : report.overallDefenseScore >= 85
        ? 'score-numeral'
        : report.overallDefenseScore >= 60
          ? 'score-numeral score-warn'
          : 'score-numeral score-danger';

    repoMetaLine.textContent = `${report.repoName} • 走査 ${report.scannedFiles} files • ${report.durationMs}ms`;
    executiveSummaryEl.textContent = report.executiveSummary;

    engineBadge.textContent = report.geminiLiveUsed
      ? `Live ${report.analysisModeUsed} (thinking:${report.reasoningLevelUsed} • store:false)`
      : 'Deterministic STRIDE + Static Shield (0 Tokens)';

    clearChildren(telemetryStrip);
    const currentFindingIds = new Set(report.findings.map(/** @param {any} f */ (f) => String(f.id)));
    const prevSnapshot = baselineHistory.get(report.targetPath);
    if (prevSnapshot) {
      const scoreDelta = report.overallDefenseScore - prevSnapshot.score;
      let resolvedCount = 0;
      prevSnapshot.findingIds.forEach((oldId) => {
        if (!currentFindingIds.has(oldId)) resolvedCount += 1;
      });
      let newCount = 0;
      currentFindingIds.forEach((curId) => {
        if (!prevSnapshot.findingIds.has(curId)) newCount += 1;
      });
      const sign = scoreDelta >= 0 ? `+${scoreDelta}` : `${scoreDelta}`;
      const deltaClass =
        scoreDelta >= 0 && newCount === 0
          ? 'telemetry-item telemetry-delta-up'
          : 'telemetry-item telemetry-delta-down';
      telemetryStrip.appendChild(
        el(
          'span',
          deltaClass,
          `前回比: ${sign} pts（解消 ${resolvedCount} 件 / 新規 ${newCount} 件）`,
        ),
      );
    }
    baselineHistory.set(report.targetPath, {
      score: report.overallDefenseScore,
      findingIds: currentFindingIds,
    });

    const metrics = [
      `検出指摘: ${report.findings.length} 件`,
      `ローカル機密マスク保護: ${report.redactedSecretsCount} 箇所`,
      report.geminiLiveUsed ? `推定消費トークン: ~${report.tokenEstimate}` : 'API トークン消費: 0',
      `対象パス: ${report.targetPath}`,
    ];
    for (const m of metrics) {
      telemetryStrip.appendChild(el('span', 'telemetry-item', m));
    }

    const warnings = [];
    if (report.scanTruncated && report.truncationReason) {
      warnings.push(`⚠️ ${report.truncationReason}`);
    }
    if (report.geminiFallbackReason) {
      warnings.push(`⚠️ ${report.geminiFallbackReason}`);
    }
    if (warnings.length > 0) {
      setStatus(warnings.join(' / '), false);
    } else {
      setStatus(`予防脅威シミュレーション完了 (${report.repoName})`, false);
    }

    renderStackCards(report.stackSummaries);
    renderTrustGraphSvg(report.trustGraph);
    renderRoadmap(report.priorityRoadmap);
    renderStrideTable(report.strideMatrix);
    renderFindingsTable(report.findings);
    renderDestructionCertificate(report.destructionCertificate);
  }

  /**
   * @param {any} cert
   */
  function renderDestructionCertificate(cert) {
    if (!destructionCertTbody) return;
    clearChildren(destructionCertTbody);
    if (!cert) return;
    if (destructionCertBadge) {
      destructionCertBadge.textContent = cert.verified
        ? '✓ ECDSA P-256 VERIFIED • DoD 5220.22-M (3-Pass)'
        : '⚠️ UNVERIFIED';
    }
    const rows = [
      ['証明書ID (Certificate ID)', `${cert.certificateId} (${cert.issuedAt})`],
      ['対象リポジトリ保護モード', String(cert.targetReadOnlyMode)],
      [
        '一時領域隔離 & 暗号化規格',
        `ACL ${cert.ephemeralVaultAcl} + ${cert.encryptionStandard} (SHA-256: ${cert.fernetCiphertextSha256})`,
      ],
      [
        '完全消去規格 (Sanitization Standard)',
        `${cert.sanitizationStandard} (${cert.passesCompleted} パス上書き完了 • 計 ${cert.totalBytesOverwritten} bytes 消去 • Pass-3 SHA-256: ${cert.pass3OverwriteSha256})`,
      ],
      [
        '暗号署名アルゴリズム',
        `${cert.signatureAlgorithm} (検証ステータス: ${cert.verified ? 'VERIFIED' : 'FAILED'})`,
      ],
      ['公開鍵フィンガープリント (SPKI SHA-256)', String(cert.publicKeyFingerprintSha256)],
      ['ECDSA P-256 デジタル署名 (Base64URL)', String(cert.signatureBase64Url)],
    ];
    for (const [label, value] of rows) {
      const tr = el('tr');
      const th = el('th', '', label);
      th.setAttribute('scope', 'row');
      tr.appendChild(th);
      tr.appendChild(el('td', 'mono-path', value));
      destructionCertTbody.appendChild(tr);
    }
  }

  /**
   * @param {any[]} summaries
   */
  function renderStackCards(summaries) {
    clearChildren(stackGrid);
    for (const s of summaries) {
      const hasAnyFinding = s.criticalCount + s.highCount + s.mediumCount + s.lowCount > 0;
      const isStackUnscoped = s.detectedFiles === 0 && !hasAnyFinding;
      const stateClass =
        s.criticalCount + s.highCount > 0
          ? 'status-exposed'
          : isStackUnscoped
            ? 'status-attention'
            : 'status-hardened';
      const card = el('article', `card stack-card ${stateClass}`);

      const top = el('div', 'stack-card-top');
      top.appendChild(el('h3', 'stack-title', s.label));
      const scoreSpan = el('span', 'stack-score', isStackUnscoped ? 'N/A' : `${s.defenseScore}`);
      top.appendChild(scoreSpan);
      card.appendChild(top);

      card.appendChild(
        el(
          'p',
          'stack-meta',
          `対象 ${s.detectedFiles} files • Critical ${s.criticalCount} / High ${s.highCount} / Med ${s.mediumCount}`,
        ),
      );

      const tagsWrap = el('div', 'control-tags');
      if (s.verifiedControls && s.verifiedControls.length > 0) {
        for (const ctrl of s.verifiedControls.slice(0, 3)) {
          tagsWrap.appendChild(el('span', 'control-tag', `✓ ${ctrl}`));
        }
      } else {
        tagsWrap.appendChild(
          el(
            'span',
            s.criticalCount + s.highCount > 0 ? 'pill pill-crimson' : 'telemetry-item',
            s.criticalCount + s.highCount > 0
              ? '⚠️ 防御パッチ要適用'
              : isStackUnscoped
                ? '対象外 (0 files)'
                : '指摘なし (対象ファイル走査済)',
          ),
        );
      }
      card.appendChild(tagsWrap);
      stackGrid.appendChild(card);
    }
  }

  /**
   * Builds accessible SVG trust-boundary architecture map via createElementNS (zero innerHTML).
   * @param {{ nodes: any[], edges: any[] }} graph
   */
  function renderTrustGraphSvg(graph) {
    clearChildren(trustMapContainer);
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 880 210');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', '4層信頼境界ステータス図');

    const positions = [
      { x: 20, y: 45 },
      { x: 238, y: 45 },
      { x: 456, y: 45 },
      { x: 674, y: 45 },
    ];

    // Draw edges first
    graph.edges.forEach((edge, idx) => {
      const p1 = positions[idx];
      const p2 = positions[idx + 1];
      if (!p1 || !p2) return;

      const line = document.createElementNS(ns, 'line');
      line.setAttribute('x1', String(p1.x + 186));
      line.setAttribute('y1', String(p1.y + 55));
      line.setAttribute('x2', String(p2.x));
      line.setAttribute('y2', String(p2.y + 55));
      line.setAttribute('stroke', edge.riskLevel === 'high' ? '#e11d48' : '#0284c7');
      line.setAttribute('stroke-width', '2.5');
      if (edge.riskLevel === 'high') {
        line.setAttribute('stroke-dasharray', '5 4');
      }
      svg.appendChild(line);

      const protoLabel = document.createElementNS(ns, 'text');
      protoLabel.setAttribute('x', String((p1.x + 186 + p2.x) / 2));
      protoLabel.setAttribute('y', '28');
      protoLabel.setAttribute('text-anchor', 'middle');
      protoLabel.setAttribute('fill', '#0369a1');
      protoLabel.setAttribute('font-size', '10');
      protoLabel.setAttribute('font-weight', '500');
      protoLabel.textContent = edge.protocol;
      svg.appendChild(protoLabel);
    });

    // Draw trust boundary nodes
    graph.nodes.forEach((node, idx) => {
      const pos = positions[idx] || { x: 20 + idx * 215, y: 45 };
      const strokeColor =
        node.status === 'exposed'
          ? '#e11d48'
          : node.status === 'attention'
            ? '#d97706'
            : '#059669';
      const fillBg =
        node.status === 'exposed'
          ? '#fff1f2'
          : node.status === 'attention'
            ? '#fffbeb'
            : '#ecfdf5';

      const g = document.createElementNS(ns, 'g');

      const rect = document.createElementNS(ns, 'rect');
      rect.setAttribute('x', String(pos.x));
      rect.setAttribute('y', String(pos.y));
      rect.setAttribute('width', '186');
      rect.setAttribute('height', '114');
      rect.setAttribute('rx', '10');
      rect.setAttribute('fill', fillBg);
      rect.setAttribute('stroke', strokeColor);
      rect.setAttribute('stroke-width', '1.8');
      g.appendChild(rect);

      const zoneTxt = document.createElementNS(ns, 'text');
      zoneTxt.setAttribute('x', String(pos.x + 14));
      zoneTxt.setAttribute('y', String(pos.y + 24));
      zoneTxt.setAttribute('fill', '#0369a1');
      zoneTxt.setAttribute('font-size', '9.5');
      zoneTxt.setAttribute('font-weight', '600');
      zoneTxt.textContent = `ZONE: ${String(node.zone).toUpperCase()}`;
      g.appendChild(zoneTxt);

      const titleTxt = document.createElementNS(ns, 'text');
      titleTxt.setAttribute('x', String(pos.x + 14));
      titleTxt.setAttribute('y', String(pos.y + 48));
      titleTxt.setAttribute('fill', '#0f172a');
      titleTxt.setAttribute('font-size', '12.5');
      titleTxt.setAttribute('font-weight', '600');
      titleTxt.textContent = node.label;
      g.appendChild(titleTxt);

      const statusTxt = document.createElementNS(ns, 'text');
      statusTxt.setAttribute('x', String(pos.x + 14));
      statusTxt.setAttribute('y', String(pos.y + 74));
      statusTxt.setAttribute('fill', strokeColor);
      statusTxt.setAttribute('font-size', '11.5');
      statusTxt.setAttribute('font-weight', '600');
      statusTxt.textContent =
        node.findingCount > 0 ? `⚠️ リスク検出 ${node.findingCount} 件` : '✓ 防御境界パス';
      g.appendChild(statusTxt);

      const subTxt = document.createElementNS(ns, 'text');
      subTxt.setAttribute('x', String(pos.x + 14));
      subTxt.setAttribute('y', String(pos.y + 96));
      subTxt.setAttribute('fill', '#475569');
      subTxt.setAttribute('font-size', '10');
      subTxt.textContent = String(node.summary).slice(0, 22);
      g.appendChild(subTxt);

      svg.appendChild(g);
    });

    trustMapContainer.appendChild(svg);
  }

  /**
   * @param {any[]} steps
   */
  function renderRoadmap(steps) {
    clearChildren(roadmapList);
    for (const step of steps) {
      const li = el('li', 'roadmap-step');
      li.appendChild(el('div', 'roadmap-phase', `${step.phase} • ${formatStackLabel(step.targetStack)}`));
      li.appendChild(el('h3', 'roadmap-title', step.title));
      li.appendChild(el('p', 'roadmap-action', step.action));
      roadmapList.appendChild(li);
    }
  }

  /**
   * @param {number} value
   * @param {string} fillClass
   */
  function createMeter(value, fillClass) {
    const wrap = el('span', 'meter-inline');
    const track = el('span', 'meter-track');
    const fill = el('span', `meter-fill ${fillClass}`);
    fill.style.width = `${Math.max(4, Math.min(100, value))}%`;
    track.appendChild(fill);
    wrap.appendChild(track);
    wrap.appendChild(el('span', '', `${value}%`));
    return wrap;
  }

  /**
   * @param {any[]} strideItems
   */
  function renderStrideTable(strideItems) {
    clearChildren(strideTbody);
    for (const item of strideItems) {
      const tr = el('tr');
      const th = el('th', '', item.category);
      th.setAttribute('scope', 'row');
      tr.appendChild(th);

      const tdExposure = el('td');
      tdExposure.appendChild(
        createMeter(
          item.exposureScore,
          item.exposureScore >= 45 ? 'fill-crimson' : 'fill-blue',
        ),
      );
      tr.appendChild(tdExposure);

      const tdReadiness = el('td');
      tdReadiness.appendChild(createMeter(item.readinessScore, 'fill-emerald'));
      tr.appendChild(tdReadiness);

      tr.appendChild(el('td', '', item.topRiskSummary));
      tr.appendChild(el('td', '', item.primaryDefense));
      strideTbody.appendChild(tr);
    }
  }

  /**
   * @param {any[]} findings
   */
  function renderFindingsTable(findings) {
    clearChildren(findingsTbody);
    const filtered =
      activeStackFilter === 'all'
        ? findings
        : findings.filter((f) => f.stack === activeStackFilter);

    if (filtered.length === 0) {
      const tr = el('tr');
      const th = el('th', '', '✓ 指摘なし');
      th.setAttribute('scope', 'row');
      tr.appendChild(th);
      const td = el('td', '', '選択されたスタック範囲で構造的露出は検出されませんでした。');
      td.setAttribute('colspan', '5');
      tr.appendChild(td);
      findingsTbody.appendChild(tr);
      return;
    }

    for (const f of filtered) {
      const tr = el('tr');

      const th = el('th');
      th.setAttribute('scope', 'row');
      const badge = el('span', severityBadgeClass(f.severity), `${f.ruleId} • ${String(f.severity).toUpperCase()}`);
      th.appendChild(badge);
      tr.appendChild(th);

      tr.appendChild(el('td', '', formatStackLabel(f.stack)));
      tr.appendChild(el('td', 'mono-path', `${f.filePath}:${f.line}`));
      tr.appendChild(el('td', '', `${f.stride} (${f.cwe})`));
      tr.appendChild(el('td', '', f.title));

      const tdAction = el('td');
      const openBtn = /** @type {HTMLButtonElement} */ (
        el('button', 'btn btn-outline btn-sm', '防御パッチを表示')
      );
      openBtn.type = 'button';
      openBtn.addEventListener('click', () => openPatchModal(f));
      tdAction.appendChild(openBtn);
      tr.appendChild(tdAction);

      findingsTbody.appendChild(tr);
    }
  }

  /**
   * @param {any} finding
   */
  function openPatchModal(finding) {
    dialogMetaKicker.textContent = `${finding.ruleId} • ${finding.cwe} • ${finding.owaspAsvs}`;
    dialogTitle.textContent = finding.title;
    dialogLocation.textContent = `${finding.filePath} (Line ${finding.line})`;
    dialogSnippet.textContent = finding.snippetRedacted;
    dialogRootCause.textContent = finding.rootCause;
    dialogPatch.textContent = finding.defensivePatch;
    dialogVerify.textContent = finding.verificationHint;
    copyPatchBtn.textContent = 'パッチをコピー';
    dialog.showModal();
  }

  copyPatchBtn.addEventListener('click', async () => {
    const text = dialogPatch.textContent || '';
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      copyPatchBtn.textContent = '✓ コピー完了';
    } catch {
      copyPatchBtn.textContent = '選択してコピーしてください';
    }
  });

  /**
   * @param {{ targetPath: string, mode: string, apiKey?: string, excludeFixtures?: boolean }} reqData
   */
  async function runAuditRequest(reqData) {
    setStatus('静的ルール走査 & 信頼境界脅威シミュレーションを実行中...', false);
    try {
      const response = await fetch('/api/audit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Longinus-Csrf': csrfToken,
        },
        body: JSON.stringify(reqData),
      });
      const json = await response.json();
      if (!response.ok) {
        setStatus(`エラー: ${json.error || '監査リクエストに失敗しました。'}`, true);
        return;
      }
      latestExcludeFixtures = Boolean(reqData.excludeFixtures);
      renderReport(json);
    } catch (err) {
      setStatus(`通信エラー: ${err instanceof Error ? err.message : String(err)}`, true);
    }
  }

  // Filter buttons
  document.querySelectorAll('[data-stack-filter]').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('[data-stack-filter]').forEach((b) => b.classList.remove('chip-active'));
      btn.classList.add('chip-active');
      activeStackFilter = btn.getAttribute('data-stack-filter') || 'all';
      if (latestReport) {
        renderFindingsTable(latestReport.findings);
      }
    });
  });

  // Form submit
  const form = document.getElementById('audit-form');
  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const targetPath = targetInput.value.trim();
      if (!targetPath) {
        setStatus('エラー: ローカルリポジトリのパスを入力してください。', true);
        return;
      }
      const payload = {
        targetPath,
        mode: modeSelect.value,
        excludeFixtures: excludeFixturesFlag && targetPath === presets.selfPath,
      };
      if (apiKeyInput.value.trim()) {
        payload.apiKey = apiKeyInput.value.trim();
      }
      void runAuditRequest(payload);
    });
  }

  // Presets
  const fixtureBtn = document.getElementById('preset-fixture-btn');
  if (fixtureBtn) {
    fixtureBtn.addEventListener('click', () => {
      excludeFixturesFlag = false;
      targetInput.value = presets.fixturePath;
      void runAuditRequest({
        targetPath: presets.fixturePath,
        mode: modeSelect.value,
        ...(apiKeyInput.value.trim() ? { apiKey: apiKeyInput.value.trim() } : {}),
      });
    });
  }

  const selfBtn = document.getElementById('preset-self-btn');
  if (selfBtn) {
    selfBtn.addEventListener('click', () => {
      excludeFixturesFlag = true;
      targetInput.value = presets.selfPath;
      void runAuditRequest({
        targetPath: presets.selfPath,
        mode: modeSelect.value,
        excludeFixtures: true,
        ...(apiKeyInput.value.trim() ? { apiKey: apiKeyInput.value.trim() } : {}),
      });
    });
  }

  /**
   * @param {any} portfolio
   */
  function renderPortfolioMatrix(portfolio) {
    if (!portfolioSection || !portfolioKpis || !portfolioTbody) return;
    portfolioSection.hidden = false;

    clearChildren(portfolioKpis);
    const fleetMetrics = [
      `対象プロダクト: ${portfolio.totalRepos} 件`,
      `平均防御スコア: ${portfolio.averageDefenseScore} / 100`,
      `Critical 要対処: ${portfolio.criticalReposCount} リポジトリ`,
      `ローカル保護機密: ${portfolio.totalRedactedSecrets} 箇所`,
    ];
    for (const item of fleetMetrics) {
      portfolioKpis.appendChild(el('span', 'telemetry-item', item));
    }

    clearChildren(portfolioTbody);
    for (const repo of portfolio.repos) {
      const tr = el('tr');

      const th = el('th', '', repo.dirName);
      th.setAttribute('scope', 'row');
      tr.appendChild(th);

      const tdScore = el('td');
      const scoreBadgeClass =
        repo.overallDefenseScore >= 85
          ? 'pill pill-emerald'
          : repo.overallDefenseScore >= 60
            ? 'pill pill-amber'
            : 'pill pill-crimson';
      tdScore.appendChild(el('span', scoreBadgeClass, `${repo.overallDefenseScore} / 100`));
      tr.appendChild(tdScore);

      const truncTag = repo.scanTruncated ? ' (部分走査)' : '';
      tr.appendChild(el('td', '', `${repo.scannedFiles} files${truncTag}`));

      const tdCounts = el(
        'td',
        '',
        repo.criticalCount + repo.highCount > 0
          ? `⚠️ C:${repo.criticalCount} / H:${repo.highCount} / M:${repo.mediumCount}`
          : `✓ C:0 / H:0 / M:${repo.mediumCount}`,
      );
      tr.appendChild(tdCounts);

      tr.appendChild(el('td', '', repo.topAction));

      const tdAction = el('td');
      const inspectBtn = /** @type {HTMLButtonElement} */ (
        el('button', 'btn btn-outline btn-sm', '詳細分析')
      );
      inspectBtn.type = 'button';
      inspectBtn.addEventListener('click', () => {
        const isSelf = repo.targetPath === presets.selfPath;
        excludeFixturesFlag = isSelf;
        targetInput.value = repo.targetPath;
        void runAuditRequest({
          targetPath: repo.targetPath,
          mode: modeSelect.value,
          ...(isSelf ? { excludeFixtures: true } : {}),
          ...(apiKeyInput.value.trim() ? { apiKey: apiKeyInput.value.trim() } : {}),
        });
        overallScoreEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
      });
      tdAction.appendChild(inspectBtn);
      tr.appendChild(tdAction);

      portfolioTbody.appendChild(tr);
    }
  }

  const portfolioBtn = document.getElementById('preset-portfolio-btn');
  if (portfolioBtn) {
    portfolioBtn.addEventListener('click', async () => {
      setStatus('ローカル全プロダクトの読取専用・0トークン予防姿勢監査を実行中...', false);
      try {
        const res = await fetch('/api/portfolio', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Longinus-Csrf': csrfToken,
          },
          body: '{}',
        });
        const json = await res.json();
        if (!res.ok) {
          setStatus(`エラー: ${json.error || '一括監査リクエストに失敗しました。'}`, true);
          return;
        }
        renderPortfolioMatrix(json);
        setStatus(
          `全 ${json.totalRepos} プロダクトの一括防御姿勢監査が完了しました（平均スコア ${json.averageDefenseScore}/100 • ${json.durationMs}ms）。`,
          false,
        );
      } catch (err) {
        setStatus(`通信エラー: ${err instanceof Error ? err.message : String(err)}`, true);
      }
    });
  }

  const closePortfolioBtn = document.getElementById('close-portfolio-btn');
  if (closePortfolioBtn && portfolioSection) {
    closePortfolioBtn.addEventListener('click', () => {
      portfolioSection.hidden = true;
    });
  }

  // Export Markdown Hardening Plan
  const exportBtn = document.getElementById('export-md-btn');
  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      if (!latestReport) return;
      const lines = [
        `# LONGINUS Defensive Posture Report — ${latestReport.repoName}`,
        '',
        `- **Audited At**: ${latestReport.auditedAt}`,
        `- **Target Path**: \`${latestReport.targetPath}\``,
        `- **Overall Defense Score**: **${latestReport.overallDefenseScore} / 100**`,
        `- **Scanned Files**: ${latestReport.scannedFiles} (Redacted Secrets Protected: ${latestReport.redactedSecretsCount})`,
        '',
        '## Executive Preventive Summary',
        latestReport.executiveSummary,
        '',
        '## STRIDE Threat Exposure Matrix',
        '| Category | Exposure | Readiness | Primary Defense |',
        '|---|---:|---:|---|',
        ...latestReport.strideMatrix.map(
          /** @param {any} s */ (s) =>
            `| ${s.category} | ${s.exposureScore}% | ${s.readinessScore}% | ${s.primaryDefense} |`,
        ),
        '',
        '## Actionable Defensive Patches',
        ...latestReport.findings.flatMap(
          /** @param {any} f */ (f) => [
            `### [${f.ruleId}] ${f.title} (${f.severity.toUpperCase()})`,
            `- **File**: \`${f.filePath}:${f.line}\` | **STRIDE**: ${f.stride} | **CWE**: ${f.cwe}`,
            `- **Root Cause**: ${f.rootCause}`,
            '```',
            f.defensivePatch,
            '```',
            '',
          ],
        ),
        ...(latestReport.destructionCertificate
          ? [
              '## DoD 5220.22-M 3-Pass Sanitization & ECDSA P-256 Signed Certificate of Data Destruction',
              `- **Certificate ID**: \`${latestReport.destructionCertificate.certificateId}\` (${latestReport.destructionCertificate.issuedAt})`,
              `- **Target Repository Protection**: \`${latestReport.destructionCertificate.targetReadOnlyMode}\``,
              `- **Ephemeral Vault & Encryption**: \`ACL ${latestReport.destructionCertificate.ephemeralVaultAcl}\` + \`${latestReport.destructionCertificate.encryptionStandard}\` (SHA-256: \`${latestReport.destructionCertificate.fernetCiphertextSha256}\`)`,
              `- **Sanitization Standard**: \`${latestReport.destructionCertificate.sanitizationStandard}\` (${latestReport.destructionCertificate.passesCompleted} passes completed • ${latestReport.destructionCertificate.totalBytesOverwritten} total bytes overwritten • Pass-3 SHA-256: \`${latestReport.destructionCertificate.pass3OverwriteSha256}\`)`,
              `- **Signature Algorithm**: \`${latestReport.destructionCertificate.signatureAlgorithm}\` (Verification Status: \`${latestReport.destructionCertificate.verified ? 'VERIFIED' : 'FAILED'}\`)`,
              `- **Public Key Fingerprint (SPKI SHA-256)**: \`${latestReport.destructionCertificate.publicKeyFingerprintSha256}\``,
              `- **ECDSA P-256 Digital Signature (Base64URL)**: \`${latestReport.destructionCertificate.signatureBase64Url}\``,
              '',
            ]
          : []),
      ];

      const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `longinus-defense-report-${latestReport.repoName}.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  }

  // Export SARIF 2.1.0 Report via canonical server serializer
  const exportSarifBtn = document.getElementById('export-sarif-btn');
  if (exportSarifBtn) {
    exportSarifBtn.addEventListener('click', async () => {
      if (!latestReport) return;
      try {
        const res = await fetch('/api/sarif', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Longinus-Csrf': csrfToken,
          },
          body: JSON.stringify({
            targetPath: latestReport.targetPath,
            mode: 'deterministic',
            excludeFixtures: latestExcludeFixtures,
          }),
        });
        if (!res.ok) {
          setStatus('エラー: SARIF レポート生成に失敗しました。', true);
          return;
        }
        const sarifText = await res.text();
        const blob = new Blob([sarifText], { type: 'application/sarif+json;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `longinus-defense-report-${latestReport.repoName}.sarif`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setStatus(`SARIF 2.1.0 レポートを出力しました (${latestReport.repoName})`, false);
      } catch (err) {
        setStatus(`通信エラー: ${err instanceof Error ? err.message : String(err)}`, true);
      }
    });
  }

  // Initial bootstrap: load presets & run initial polyglot sample simulation
  async function bootstrap() {
    try {
      const res = await fetch('/api/presets', {
        headers: { 'X-Longinus-Csrf': csrfToken },
      });
      if (res.ok) {
        presets = await res.json();
        targetInput.value = presets.fixturePath || presets.selfPath;
        if (!presets.envApiKeyConfigured) {
          modeSelect.value = 'deterministic';
        }
        if (targetInput.value) {
          await runAuditRequest({
            targetPath: targetInput.value,
            mode: modeSelect.value,
          });
        }
      }
    } catch {
      setStatus('初期化待機中 — リポジトリパスを指定して実行してください。', false);
    }
  }

  void bootstrap();
})();
