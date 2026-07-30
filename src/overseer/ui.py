"""Static operator console served by the loopback API."""

from __future__ import annotations


OPERATOR_CONSOLE_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Overseer</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #050506;
      --deck: #08080b;
      --panel: #101017;
      --panel-2: #171621;
      --line: #383447;
      --line-hot: #f6be63;
      --text: #fff6e8;
      --muted: #b8b0c8;
      --lcars-amber: #f2b84b;
      --lcars-orange: #ff8f35;
      --lcars-peach: #ffc08f;
      --lcars-lavender: #b9a6ff;
      --lcars-violet: #7f69ff;
      --lcars-blue: #4ea4ff;
      --lcars-cyan: #78d6ff;
      --lcars-pink: #ef80b8;
      --good: #76d6ff;
      --warn: #f2b84b;
      --bad: #ff5f61;
      --pending: #b9a6ff;
      --inactive: #6f6a83;
      --focus: #78d6ff;
      --command: #f2b84b;
      --ops: #7f69ff;
      --alert: #ff5f61;
      --station-accent: var(--lcars-amber);
      --station-accent-2: var(--lcars-orange);
      --station-accent-3: var(--lcars-peach);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-width: 320px;
      background:
        linear-gradient(90deg, rgba(242, 184, 75, 0.08) 0 12px, transparent 12px 100%),
        linear-gradient(180deg, #050506 0%, #09080d 62%, #050506 100%),
        var(--bg);
      color: var(--text);
      font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    body[data-station="overview"] { --station-accent: var(--lcars-amber); --station-accent-2: var(--lcars-orange); --station-accent-3: var(--lcars-peach); }
    body[data-station="driver"] { --station-accent: var(--lcars-cyan); --station-accent-2: var(--lcars-violet); --station-accent-3: var(--lcars-amber); }
    body[data-station="admin"] { --station-accent: var(--lcars-peach); --station-accent-2: var(--lcars-amber); --station-accent-3: var(--lcars-cyan); }
    body[data-station="assets"] { --station-accent: var(--lcars-orange); --station-accent-2: var(--lcars-violet); --station-accent-3: var(--lcars-peach); }
    body[data-station="claims"] { --station-accent: var(--lcars-violet); --station-accent-2: var(--lcars-lavender); --station-accent-3: var(--lcars-cyan); }
    body[data-station="security"] { --station-accent: var(--bad); --station-accent-2: var(--lcars-orange); --station-accent-3: var(--warn); }
    body[data-station="health"] { --station-accent: var(--lcars-cyan); --station-accent-2: var(--lcars-blue); --station-accent-3: var(--lcars-lavender); }
    body[data-station="usage"] { --station-accent: var(--lcars-pink); --station-accent-2: var(--lcars-lavender); --station-accent-3: var(--lcars-amber); }
    body[data-station="ezri"] { --station-accent: var(--lcars-lavender); --station-accent-2: var(--lcars-cyan); --station-accent-3: var(--lcars-peach); }
    body[data-station="audit"] { --station-accent: var(--inactive); --station-accent-2: var(--lcars-amber); --station-accent-3: var(--lcars-violet); }
    button, input, select, textarea {
      font: inherit;
    }
    .shell {
      min-height: 100vh;
      display: grid;
      grid-template-columns: 294px minmax(0, 1fr);
    }
    aside {
      position: relative;
      background:
        linear-gradient(180deg, #08080b, #050506 58%, #090711),
        var(--deck);
      color: var(--text);
      padding: 18px 14px 18px 18px;
      border-right: 4px solid var(--lcars-amber);
      box-shadow: inset -18px 0 0 #000, inset -25px 0 0 var(--lcars-orange);
    }
    aside::before {
      content: "";
      display: block;
      height: 34px;
      margin-bottom: 14px;
      border-radius: 18px 18px 0 18px;
      background:
        linear-gradient(90deg, var(--lcars-amber) 0 44%, #000 44% 47%, var(--lcars-peach) 47% 69%, #000 69% 72%, var(--lcars-violet) 72% 100%);
    }
    main {
      min-width: 0;
      padding: 16px 20px 28px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 18px;
      padding-right: 20px;
    }
    .mark {
      width: 58px;
      height: 44px;
      border-radius: 22px 4px 4px 22px;
      background: linear-gradient(90deg, var(--lcars-orange), var(--lcars-amber));
      color: #09080d;
      display: grid;
      place-items: center;
      font-weight: 800;
      box-shadow: inset -10px 0 0 var(--lcars-peach);
    }
    h1, h2, h3, p { margin: 0; }
    h1 { font-size: 22px; font-weight: 820; letter-spacing: 0; text-transform: uppercase; }
    h2 { font-size: 17px; font-weight: 720; }
    h3 {
      font-size: 12px;
      font-weight: 780;
      color: var(--lcars-peach);
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    .nav {
      display: grid;
      gap: 8px;
      padding-right: 20px;
    }
    .nav button {
      width: 100%;
      border: 1px solid transparent;
      border-radius: 18px 4px 4px 18px;
      padding: 10px 12px;
      background: var(--lcars-lavender);
      color: #08080b;
      text-align: left;
      cursor: pointer;
      min-height: 40px;
      font-weight: 800;
      text-transform: uppercase;
      box-shadow: inset -16px 0 0 rgba(0, 0, 0, 0.18);
    }
    .nav button:nth-child(2n) { background: var(--lcars-amber); }
    .nav button:nth-child(3n) { background: var(--lcars-peach); }
    .nav button:nth-child(4n) { background: var(--lcars-violet); color: #fff6e8; }
    .nav button[aria-selected="true"] {
      background: var(--station-accent);
      color: #050506;
      border-color: #000;
      box-shadow: inset -20px 0 0 var(--station-accent-2), 0 0 0 2px #000;
    }
    .topbar {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: center;
      margin-bottom: 16px;
      padding: 10px 14px 10px 22px;
      border: 0;
      border-radius: 0 22px 22px 0;
      background:
        linear-gradient(90deg, var(--station-accent) 0 14px, #000 14px 20px, rgba(16, 16, 23, 0.96) 20px 100%);
      box-shadow: inset 0 -4px 0 var(--station-accent-2);
    }
    .status-line {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      color: var(--muted);
    }
    .token {
      display: flex;
      gap: 8px;
      align-items: center;
    }
    .token input {
      width: 270px;
      min-width: 0;
      border: 2px solid #000;
      border-radius: 16px 4px 4px 16px;
      padding: 8px 10px;
      background: #171621;
      color: var(--text);
    }
    .token input:focus {
      outline: 2px solid rgba(122, 183, 216, 0.42);
      border-color: var(--focus);
    }
    .icon-btn, .action-btn {
      border: 2px solid #000;
      border-radius: 16px 4px 4px 16px;
      min-height: 36px;
      background: var(--lcars-amber);
      color: #050506;
      cursor: pointer;
      font-weight: 800;
      text-transform: uppercase;
      box-shadow: inset -10px 0 0 rgba(0, 0, 0, 0.14);
    }
    .icon-btn:hover, .action-btn:hover {
      background: var(--lcars-cyan);
      color: #050506;
    }
    .icon-btn {
      width: 38px;
      display: grid;
      place-items: center;
    }
    .action-btn {
      padding: 7px 12px;
    }
    button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible {
      outline: 3px solid var(--focus);
      outline-offset: 2px;
    }
    button[disabled] {
      cursor: not-allowed;
      opacity: 0.55;
    }
    .layout-mode {
      position: fixed;
      top: 8px;
      right: 8px;
      z-index: 10;
      min-width: 116px;
      min-height: 44px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(12, minmax(0, 1fr));
      gap: 12px;
    }
    .panel {
      position: relative;
      background:
        linear-gradient(90deg, var(--panel) 0 100%),
        var(--panel);
      border: 1px solid rgba(185, 166, 255, 0.28);
      border-radius: 0 18px 4px 0;
      padding: 14px 14px 14px 22px;
      min-width: 0;
      box-shadow: inset 0 2px 0 rgba(255, 255, 255, 0.05), inset 7px 0 0 var(--lcars-lavender), 0 14px 32px rgba(0, 0, 0, 0.22);
    }
    .panel::before {
      content: "";
      position: absolute;
      inset: 0 auto auto 0;
      width: 7px;
      height: 54px;
      background: var(--station-accent);
      border-radius: 0 0 4px 0;
    }
    .panel.good { box-shadow: inset 7px 0 0 var(--good), 0 14px 32px rgba(0, 0, 0, 0.22); }
    .panel.warn { box-shadow: inset 7px 0 0 var(--warn), 0 14px 32px rgba(0, 0, 0, 0.22); }
    .panel.bad { box-shadow: inset 7px 0 0 var(--bad), 0 14px 32px rgba(0, 0, 0, 0.22); }
    .panel.pending { box-shadow: inset 7px 0 0 var(--pending), 0 14px 32px rgba(0, 0, 0, 0.22); }
    .panel.inactive { box-shadow: inset 7px 0 0 var(--inactive), 0 14px 32px rgba(0, 0, 0, 0.22); }
    .panel.good::before { background: var(--good); }
    .panel.warn::before { background: var(--warn); }
    .panel.bad::before { background: var(--bad); }
    .panel.pending::before { background: var(--pending); }
    .panel.inactive::before { background: var(--inactive); }
    .span-3 { grid-column: span 3; }
    .span-4 { grid-column: span 4; }
    .span-6 { grid-column: span 6; }
    .span-8 { grid-column: span 8; }
    .span-12 { grid-column: span 12; }
    .metric {
      display: grid;
      gap: 6px;
      min-height: 104px;
      padding-left: 24px;
      text-align: left;
      color: var(--text);
    }
    button.metric,
    button.crew-card,
    .cell-link {
      cursor: pointer;
    }
    button.metric,
    button.crew-card {
      width: 100%;
      border: 1px solid rgba(185, 166, 255, 0.28);
      font: inherit;
    }
    button.metric:hover,
    button.crew-card:hover {
      border-color: var(--focus);
      filter: brightness(1.08);
    }
    .metric .value {
      font-size: 30px;
      line-height: 1;
      font-weight: 780;
    }
    .cell-link {
      border: 0;
      padding: 0;
      background: transparent;
      color: var(--lcars-cyan);
      text-align: left;
      text-decoration: underline;
      overflow-wrap: anywhere;
    }
    .muted { color: var(--muted); }
    .pill {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      padding: 2px 10px;
      border-radius: 999px 4px 4px 999px;
      border: 2px solid #000;
      background: var(--lcars-lavender);
      color: #050506;
      font-size: 12px;
      font-weight: 800;
      white-space: nowrap;
    }
    .pill.good { color: #050506; background: var(--good); }
    .pill.warn { color: #050506; background: var(--warn); }
    .pill.bad { color: #050506; background: var(--bad); }
    .pill.pending { color: #050506; background: var(--pending); }
    .pill.inactive { color: #050506; background: var(--inactive); }
    .mini-metrics {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin: 10px 0 12px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }
    .table-scroll {
      width: 100%;
      max-width: 100%;
      overflow-x: auto;
    }
    th, td {
      border-bottom: 1px solid rgba(185, 166, 255, 0.18);
      padding: 8px 6px;
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    th {
      color: var(--lcars-peach);
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
    }
    tr:last-child td { border-bottom: 0; }
    .section {
      display: none;
    }
    .section.active {
      display: block;
    }
    .stack {
      display: grid;
      gap: 12px;
    }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 10px;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    .decision-card .list {
      margin: 10px 0;
    }
    .decision-card details {
      margin: 10px 0;
      padding: 10px;
      border: 1px solid rgba(185, 166, 255, 0.18);
      background: rgba(7, 6, 14, 0.46);
    }
    .decision-card summary {
      cursor: pointer;
      color: var(--lcars-peach);
      font-weight: 800;
    }
    .review-brief {
      display: grid;
      gap: 8px;
      margin-top: 10px;
    }
    .review-brief .row {
      display: grid;
      grid-template-columns: minmax(120px, 0.34fr) minmax(0, 1fr);
      gap: 10px;
      align-items: start;
    }
    .decision-card .action-btn[disabled] {
      cursor: not-allowed;
      opacity: 0.62;
      filter: grayscale(0.35);
    }
    .form-grid {
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 10px;
      align-items: end;
    }
    .field {
      display: grid;
      gap: 4px;
      min-width: 0;
    }
    .field.span-1 { grid-column: span 1; }
    .field.span-2 { grid-column: span 2; }
    .field.span-3 { grid-column: span 3; }
    .field.span-4 { grid-column: span 4; }
    .field.span-5 { grid-column: span 5; }
    .field.span-6 { grid-column: span 6; }
    .field.span-8, .field.span-9, .field.span-12 { grid-column: span 6; }
    label {
      color: var(--lcars-peach);
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
    }
    .field input, .field select, .field textarea {
      width: 100%;
      min-height: 36px;
      border: 2px solid #000;
      border-radius: 14px 4px 4px 14px;
      padding: 7px 9px;
      background: #171621;
      color: var(--text);
      min-width: 0;
    }
    .field textarea {
      min-height: 86px;
      resize: vertical;
    }
    .field input:focus, .field select:focus, .field textarea:focus {
      outline: 2px solid rgba(122, 183, 216, 0.34);
      border-color: var(--focus);
    }
    .action-status {
      margin-bottom: 12px;
    }
    .section-head {
      grid-column: span 12;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      justify-content: space-between;
      min-height: 42px;
      padding: 4px 12px 4px 18px;
      border-radius: 22px 4px 4px 22px;
      background:
        linear-gradient(90deg, var(--station-accent-2) 0 22px, #000 22px 28px, var(--station-accent) 28px 58%, #000 58% 60%, var(--station-accent-3) 60% 100%);
      color: #050506;
    }
    .section-head h3 {
      color: #050506;
      font-size: 13px;
    }
    .section-head .pill,
    .section-head .action-btn {
      border-color: #050506;
    }
    .list {
      display: grid;
      gap: 8px;
    }
    .row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 45%);
      gap: 10px;
      align-items: center;
      padding: 9px 0;
      border-bottom: 1px solid rgba(185, 166, 255, 0.16);
    }
    .row span, .row strong {
      min-width: 0;
      overflow-wrap: anywhere;
    }
    .row strong {
      text-align: right;
    }
    .row:last-child { border-bottom: 0; }
    .crew-card {
      min-height: 190px;
      padding-left: 24px;
    }
    .crew-card:nth-of-type(3n + 1) { box-shadow: inset 7px 0 0 var(--lcars-amber), 0 14px 32px rgba(0, 0, 0, 0.22); }
    .crew-card:nth-of-type(3n + 2) { box-shadow: inset 7px 0 0 var(--lcars-lavender), 0 14px 32px rgba(0, 0, 0, 0.22); }
    .crew-card:nth-of-type(3n) { box-shadow: inset 7px 0 0 var(--lcars-blue), 0 14px 32px rgba(0, 0, 0, 0.22); }
    .crew-card h3 {
      color: var(--lcars-amber);
    }
    .crew-card .list {
      margin-top: 10px;
    }
    .error {
      border-color: var(--bad);
      background: rgba(65, 11, 18, 0.82);
      color: #ffd7d7;
    }
    .officer-channel {
      border-radius: 0 24px 4px 0;
      background:
        linear-gradient(90deg, color-mix(in srgb, var(--station-accent) 22%, transparent), transparent 26%),
        var(--panel);
    }
    .station-intro {
      grid-column: span 12;
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(168px, auto);
      gap: 16px;
      align-items: stretch;
      min-height: 132px;
      padding: 18px 18px 18px 30px;
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 0 34px 6px 0;
      background:
        linear-gradient(90deg, var(--station-accent) 0 16px, #000 16px 24px, rgba(16, 16, 23, 0.96) 24px 100%),
        var(--panel);
      box-shadow: inset 0 -7px 0 var(--station-accent-2), 0 18px 34px rgba(0, 0, 0, 0.24);
    }
    .station-intro h2 {
      font-size: 24px;
      line-height: 1.08;
      text-transform: uppercase;
    }
    .station-intro p {
      margin-top: 8px;
      color: var(--muted);
      max-width: 780px;
    }
    .station-strip {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 14px;
    }
    .station-chip {
      display: inline-flex;
      align-items: center;
      min-height: 26px;
      padding: 3px 10px;
      border: 2px solid #000;
      border-radius: 999px 4px 4px 999px;
      background: var(--station-accent-3);
      color: #050506;
      font-size: 12px;
      font-weight: 820;
      text-transform: uppercase;
    }
    .station-code {
      display: grid;
      align-content: center;
      justify-items: end;
      gap: 8px;
      min-width: 0;
      padding: 12px 14px;
      border-radius: 28px 4px 4px 28px;
      background: var(--station-accent);
      color: #050506;
      box-shadow: inset -18px 0 0 var(--station-accent-2);
      text-align: right;
      font-weight: 840;
      text-transform: uppercase;
    }
    .station-code span:first-child {
      font-size: 28px;
      line-height: 1;
    }
    .station-code span:last-child {
      max-width: 180px;
      font-size: 11px;
      overflow-wrap: anywhere;
    }
    .kb-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }
    .kb-card {
      display: grid;
      gap: 9px;
      min-height: 180px;
      padding: 14px 14px 14px 20px;
      border: 1px solid rgba(185, 166, 255, 0.26);
      border-radius: 0 22px 4px 0;
      background:
        linear-gradient(90deg, var(--station-accent-2) 0 8px, transparent 8px 100%),
        rgba(23, 22, 33, 0.84);
    }
    .kb-card.primary {
      background:
        linear-gradient(90deg, var(--good) 0 8px, transparent 8px 100%),
        rgba(23, 22, 33, 0.92);
    }
    .kb-card h3 {
      color: var(--station-accent-3);
    }
    .kb-card .source {
      color: var(--lcars-cyan);
      overflow-wrap: anywhere;
      font-size: 12px;
    }
    @media (max-width: 900px) {
      .shell { grid-template-columns: 1fr; }
      aside {
        position: sticky;
        top: 0;
        z-index: 2;
        border-right: 0;
        border-bottom: 1px solid #2d3540;
        box-shadow: inset 0 -5px 0 rgba(199, 167, 108, 0.12);
      }
      .nav {
        grid-template-columns: repeat(4, minmax(0, 1fr));
      }
      .nav button {
        text-align: center;
        padding: 9px 7px;
      }
      .topbar {
        grid-template-columns: 1fr;
      }
      .token {
        width: 100%;
      }
      .token input {
        flex: 1;
      }
      .span-3, .span-4, .span-6, .span-8 { grid-column: span 12; }
      .field.span-1, .field.span-2, .field.span-3 { grid-column: span 6; }
      .station-intro { grid-template-columns: 1fr; }
      .station-code { justify-items: start; text-align: left; }
      .kb-grid { grid-template-columns: 1fr; }
    }
    @media (max-width: 520px) {
      main { padding: 12px; }
      aside { padding: 12px; }
      .nav { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .grid { gap: 8px; }
      .panel { padding: 11px; }
      .panel::before { height: 32px; }
      .token { flex-wrap: wrap; }
      .token input { width: 100%; flex-basis: 100%; }
      .field.span-2, .field.span-3, .field.span-6 { grid-column: span 6; }
    }
    body[data-layout-effective="tablet"] .shell,
    body[data-layout-effective="mobile"] .shell { grid-template-columns: 1fr; }
    body[data-layout-effective="tablet"] aside,
    body[data-layout-effective="mobile"] aside {
      position: static;
      border-right: 0;
      border-bottom: 4px solid var(--station-accent);
      box-shadow: none;
    }
    body[data-layout-effective="tablet"] .nav { grid-template-columns: repeat(5, minmax(0, 1fr)); }
    body[data-layout-effective="mobile"] .nav { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    body[data-layout-effective="tablet"] .span-3,
    body[data-layout-effective="tablet"] .span-4 { grid-column: span 6; }
    body[data-layout-effective="mobile"] .span-3,
    body[data-layout-effective="mobile"] .span-4,
    body[data-layout-effective="mobile"] .span-6,
    body[data-layout-effective="mobile"] .span-8 { grid-column: span 12; }
    body[data-layout-effective="mobile"] main { padding: 12px; }
    body[data-layout-effective="mobile"] .topbar { grid-template-columns: 1fr; }
    body[data-layout-effective="mobile"] .token { flex-wrap: wrap; }
    body[data-layout-effective="mobile"] .token input { width: 100%; flex-basis: 100%; }
    body[data-layout-effective="desktop"] .shell { grid-template-columns: 294px minmax(0, 1fr); }
    body[data-layout-effective="desktop"] aside {
      position: relative;
      border-right: 4px solid var(--lcars-amber);
      border-bottom: 0;
    }
    body[data-layout-effective="desktop"] .nav { grid-template-columns: 1fr; }
    body[data-layout-effective="desktop"] .span-3 { grid-column: span 3; }
    body[data-layout-effective="desktop"] .span-4 { grid-column: span 4; }
    body[data-layout-effective="desktop"] .span-6 { grid-column: span 6; }
    body[data-layout-effective="desktop"] .span-8 { grid-column: span 8; }
    #driver .action-btn { min-height: 44px; }
    .nav button[data-view="driver"],
    #driver input, #driver select { min-height: 44px; }
    body[data-layout-effective="desktop"] aside { width: min(294px, 28vw); }
    @media (max-width: 390px) {
      body[data-layout-effective="desktop"] .shell { grid-template-columns: 96px minmax(224px, 1fr); }
      body[data-layout-effective="desktop"] aside { width: 96px; padding: 8px 4px; }
      body[data-layout-effective="desktop"] .brand h1,
      body[data-layout-effective="desktop"] .brand p { display: none; }
      body[data-layout-effective="desktop"] .nav button { font-size: 10px; padding: 6px 3px; overflow-wrap: anywhere; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { scroll-behavior: auto !important; transition: none !important; animation: none !important; }
    }
  </style>
</head>
<body data-station="overview">
  <button id="layout-mode" class="action-btn layout-mode" type="button" aria-live="polite"
    aria-label="Layout preference auto; effective desktop">Layout: auto</button>
  <div class="shell">
    <aside>
      <div class="brand">
        <div class="mark">O</div>
        <div>
          <h1>Overseer</h1>
          <p class="muted">Station operations</p>
        </div>
      </div>
      <nav class="nav" aria-label="Views">
        <button data-view="overview" aria-selected="true">Overview</button>
        <button data-view="driver">AI Driver</button>
        <button data-view="admin">Admin</button>
        <button data-view="assets">Assets</button>
        <button data-view="claims">Claims</button>
        <button data-view="security">Security</button>
        <button data-view="health">Health</button>
        <button data-view="usage">Usage</button>
        <button data-view="ezri">Documents</button>
        <button data-view="audit">Audit</button>
      </nav>
    </aside>
    <main>
      <div class="topbar">
        <div>
          <h2 id="view-title">Strategic Operations</h2>
          <div class="status-line">
            <span id="overall" class="pill">loading</span>
            <span id="updated" class="muted">not refreshed</span>
          </div>
        </div>
        <form id="token-form" class="token">
          <input id="token" type="password" autocomplete="off" aria-label="Overseer API token" placeholder="Overseer API token">
          <button id="save-token" type="submit" class="action-btn">Unlock</button>
          <button id="refresh" type="button" class="icon-btn" title="Refresh" aria-label="Refresh">R</button>
        </form>
      </div>
      <div id="error" class="panel error" hidden></div>
      <div id="action-status" class="panel action-status" hidden></div>
      <section id="overview" class="section active"></section>
      <section id="driver" class="section"></section>
      <section id="admin" class="section"></section>
      <section id="assets" class="section"></section>
      <section id="claims" class="section"></section>
      <section id="security" class="section"></section>
      <section id="health" class="section"></section>
      <section id="usage" class="section"></section>
      <section id="ezri" class="section"></section>
      <section id="audit" class="section"></section>
    </main>
  </div>
  <script>
    const endpoints = {
      auth: "/auth-check",
      dashboard: "/operator-dashboard",
      incidentLifecycle: "/incidents/lifecycle",
      operations: "/operations/gap-coverage",
      operationWorkflows: "/operations/workflows",
      runtime: "/runtime-status",
      authorizations: "/admin/authorizations-required",
      readiness: "/admin/execution-readiness",
      adapters: "/admin/adapter-capabilities",
      adminArchivePlan: "/admin/history-archive-plan",
      adminArchives: "/admin/history-archives",
      activePolicy: "/admin/active-policy-profile",
      complianceEvidence: "/compliance/evidence",
      policyHelper: "/admin/policy-customization-helper",
      packageStatus: "/maintenance/package-status",
      firmwareStatus: "/maintenance/firmware-status",
      firmwarePreflight: "/maintenance/firmware-preflight",
      softwareEvidence: "/maintenance/software-evidence",
      advisories: "/maintenance/advisories",
      maintenanceSchedules: "/maintenance/schedules",
      physical: "/physical-summary",
      storageEvidence: "/storage/evidence",
      backupOperations: "/storage/backup-operations",
      virtual: "/virtual-summary",
      virtualEvidence: "/virtual/evidence",
      virtualOperations: "/virtual/operations",
      imageScans: "/virtual/image-scans",
      security: "/security-summary",
      securityEvidence: "/security/evidence",
      keyBroker: "/security/key-broker",
      identityEvidence: "/identity/evidence",
      identityRotationRequests: "/identity/rotation-requests",
      identityRotationReadiness: "/identity/rotation-readiness",
      health: "/health-efficiency",
      healthSummary: "/health-summary",
      serviceEvidence: "/health/service-evidence",
      codexUsage: "/health/codex-usage",
      observabilityTrends: "/observability/trends",
      metricHistory: "/observability/metric-history",
      performanceHistory: "/observability/performance-history",
      usage: "/usage-summary",
      usageEvidence: "/usage/evidence",
      remoteTesting: "/usage/remote-testing",
      documentsStatus: "/documents/status",
      documentationEvidence: "/documents/evidence",
      gitStatus: "/git/status",
      documentsNotes: "/documents/notes?folder=Overseer",
      knowledgeCapturePlan: "/documents/knowledge-capture-plan?limit=12",
      crewMessages: "/crew/messages",
      audit: "/audit-summary",
      approvals: "/approvals-summary",
      claims: "/claims/review",
      claimCleanup: "/claims/cleanup-plan",
      listenerReviewQueue: "/host/security/listener-review-queue",
      sourceReviewQueue: "/host/security/source-review-queue"
      ,agentProviders: "/agent-providers"
      ,agentInstances: "/agent-instances"
      ,agentFailoverExecutions: "/agent-failover-executions"
      ,agentSessions: "/agent-sessions"
      ,agentDispatches: "/agent-dispatches"
      ,agentUsage: "/agent-usage"
    };
    const requiredEndpointKeys = new Set(["auth"]);
    const protectedGatewayPath = window.location.pathname === "/Overseer" || window.location.pathname.startsWith("/Overseer/");
    const apiBase = protectedGatewayPath ? "/Overseer" : "";
    const tokenStore = protectedGatewayPath ? sessionStorage : localStorage;
    const state = {
      data: {},
      view: "overview",
      token: tokenStore.getItem("overseerToken") || "",
      documentsFolder: "Overseer",
      documentsQuery: "Overseer",
      loadErrors: [],
      lastAction: null
    };
    state.driverSelection = {};
    const LAYOUT_MODES = ["auto", "desktop", "tablet", "mobile"];
    function viewportLayout(width) {
      if (width <= 700) return "mobile";
      if (width <= 1024) return "tablet";
      return "desktop";
    }
    function nextLayoutMode(mode) {
      return LAYOUT_MODES[(LAYOUT_MODES.indexOf(mode) + 1) % LAYOUT_MODES.length] || "auto";
    }
    function readLayoutMode() {
      try {
        const mode = localStorage.getItem("overseerLayoutMode");
        return LAYOUT_MODES.includes(mode) ? mode : "auto";
      } catch (_) {
        return "auto";
      }
    }
    let layoutMode = readLayoutMode();
    function applyLayoutMode() {
      const effective = layoutMode === "auto" ? viewportLayout(window.innerWidth) : layoutMode;
      document.body.dataset.layoutPreference = layoutMode;
      document.body.dataset.layoutEffective = effective;
      document.body.setAttribute("data-layout-effective", effective);
      const control = document.getElementById("layout-mode");
      control.textContent = `Layout: ${layoutMode}`;
      control.setAttribute("aria-label", `Layout preference ${layoutMode}; effective ${effective}`);
    }
    document.getElementById("layout-mode").addEventListener("click", () => {
      layoutMode = nextLayoutMode(layoutMode);
      try { localStorage.setItem("overseerLayoutMode", layoutMode); } catch (_) {}
      applyLayoutMode();
    });
    window.addEventListener("resize", () => {
      if (layoutMode === "auto") applyLayoutMode();
    });
    applyLayoutMode();
    document.body.dataset.loadState = "locked";
    document.body.dataset.loadFailures = "0";
    const tokenInput = document.getElementById("token");
    tokenInput.value = state.token;
    document.getElementById("token-form").addEventListener("submit", (event) => {
      event.preventDefault();
      state.token = tokenInput.value.trim();
      if (state.token) tokenStore.setItem("overseerToken", state.token);
      else tokenStore.removeItem("overseerToken");
      refresh();
    });
    document.getElementById("refresh").addEventListener("click", refresh);
    document.querySelectorAll(".nav button").forEach((button) => {
      button.addEventListener("click", () => selectView(button.dataset.view));
    });
    document.addEventListener("click", async (event) => {
      const fillTarget = event.target.closest("[data-fill]");
      if (fillTarget) {
        event.preventDefault();
        applyFill(fillTarget.dataset.fill);
        const targetView = fillTarget.dataset.viewTarget;
        if (targetView && targetView !== state.view && !fillTarget.dataset.action) selectView(targetView);
        if (!fillTarget.dataset.action) return;
      }
      const viewTarget = event.target.closest("[data-view-target]");
      if (viewTarget && !viewTarget.dataset.action) {
        event.preventDefault();
        selectView(viewTarget.dataset.viewTarget);
        return;
      }
      const button = event.target.closest("[data-action]");
      if (!button) return;
      event.preventDefault();
      await runAction(button.dataset.action, button);
    });
    document.addEventListener("change", (event) => {
      if (!event.target.closest("#driver")) return;
      state.driverSelection[event.target.id] = event.target.value;
      renderDriver();
    });
    function providerGate(providers, providerId, requiredCapabilities, capability) {
      const provider = (providers || []).find((row) => row.id === providerId);
      if (!provider) return {enabled: false, blocker: `Provider ${providerId || "unknown"} is not configured`};
      if (provider.available !== true || provider.readiness !== "available") {
        return {enabled: false, blocker: JSON.stringify(provider.unavailable_reason || `Provider readiness is ${provider.readiness || "unknown"}`)};
      }
      const capabilities = provider.capabilities || {};
      const missing = Object.entries(requiredCapabilities || {})
        .filter(([name, needed]) => needed === true && capabilities[name] !== true)
        .map(([name]) => name);
      if (missing.length) return {enabled: false, blocker: `Required capabilities unavailable: ${missing.join(", ")}`};
      if (capabilities[capability] !== true) return {enabled: false, blocker: `Provider does not support ${capability}`};
      return {enabled: true, blocker: ""};
    }
    function validatedTransferPayload(instanceId, incomingProviderId, initiatedBy, approvalId) {
      if (!instanceId) throw new Error("instance_id is required");
      if (!incomingProviderId) throw new Error("incoming_provider_id is required");
      if (!approvalId) throw new Error("approval_id is required");
      return {instance_id: instanceId, incoming_provider_id: incomingProviderId, initiated_by: initiatedBy || "operator", approval_id: approvalId};
    }
    function selectView(view) {
      state.view = view;
      document.body.dataset.station = view;
      document.querySelectorAll(".nav button").forEach((button) => {
        button.setAttribute("aria-selected", String(button.dataset.view === view));
      });
      document.querySelectorAll(".section").forEach((section) => {
        section.classList.toggle("active", section.id === view);
      });
      document.getElementById("view-title").textContent = title(view);
      render();
    }
    async function refresh() {
      const error = document.getElementById("error");
      document.body.dataset.loadState = "loading";
      document.body.dataset.loadFailures = "0";
      error.dataset.loadState = "loading";
      error.dataset.loadFailures = "0";
      error.hidden = true;
      let authPayload;
      try {
        authPayload = await getJson(endpoints.auth);
      } catch (err) {
        error.textContent = formatEndpointError({path: endpoints.auth, message: err.message});
        document.body.dataset.loadState = "failed";
        document.body.dataset.loadFailures = "1";
        error.dataset.loadState = "failed";
        error.dataset.loadFailures = "1";
        error.hidden = false;
        return;
      }
      state.data = {...state.data, auth: authPayload};
      state.loadErrors = [];
      document.getElementById("updated").textContent = new Date().toLocaleString();
      const endpointEntries = Object.entries(endpoints)
        .filter(([key]) => !requiredEndpointKeys.has(key))
        .map(([key, path]) => [key, endpointPath(key, path)]);
      const results = await mapEndpointEntries(endpointEntries, 4);
      const nextData = {...state.data};
      const failures = [];
      results.forEach((result, index) => {
        const [key, path] = endpointEntries[index];
        if (result.status === "fulfilled") {
          nextData[result.value[0]] = result.value[1];
        } else {
          failures.push({key, path, message: result.reason.message});
        }
      });
      state.data = nextData;
      state.loadErrors = failures;
      document.body.dataset.loadFailures = String(failures.length);
      error.dataset.loadFailures = String(failures.length);
      if (failures.length) {
        error.textContent = `Loaded with panel errors: ${failures.map(formatEndpointError).join("; ")}`;
        error.hidden = false;
      }
      try {
        document.getElementById("updated").textContent = new Date().toLocaleString();
        render();
        document.body.dataset.loadState = failures.length ? "partial" : "ready";
        error.dataset.loadState = document.body.dataset.loadState;
      } catch (err) {
        error.textContent = err.message;
        document.body.dataset.loadState = "failed";
        document.body.dataset.loadFailures = String(Math.max(1, failures.length));
        error.dataset.loadState = "failed";
        error.dataset.loadFailures = document.body.dataset.loadFailures;
        error.hidden = false;
      }
    }
    function formatEndpointError(failure) {
      return `${failure.path}: ${failure.message}`;
    }
    function endpointPath(key, path) {
      if (key === "documentsNotes") return documentsNotesPath();
      return path;
    }
    function documentsNotesPath() {
      const folder = (state.documentsFolder || "Overseer").trim();
      const suffix = folder ? `?folder=${encodeURIComponent(folder)}` : "";
      return `/documents/notes${suffix}`;
    }
    async function mapEndpointEntries(entries, concurrency) {
      const results = new Array(entries.length);
      let nextIndex = 0;
      async function worker() {
        while (nextIndex < entries.length) {
          const index = nextIndex;
          nextIndex += 1;
          const [key, path] = entries[index];
          try {
            results[index] = {status: "fulfilled", value: [key, await getJson(path)]};
          } catch (reason) {
            results[index] = {status: "rejected", reason};
          }
        }
      }
      await Promise.all(Array.from({length: Math.min(concurrency, entries.length)}, worker));
      return results;
    }
    async function getJson(path) {
      const headers = {};
      const token = tokenInput.value.trim() || state.token;
      if (token) headers.authorization = `Bearer ${token}`;
      const target = `${apiBase}${path}`;
      let response;
      try {
        response = await fetch(target, {headers});
      } catch (err) {
        throw new Error(`request failed at ${target}`);
      }
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    }
    async function postJson(path, payload = {}) {
      const headers = {"content-type": "application/json"};
      const token = tokenInput.value.trim() || state.token;
      if (token) headers.authorization = `Bearer ${token}`;
      const response = await fetch(`${apiBase}${path}`, {method: "POST", headers, body: JSON.stringify(payload)});
      if (!response.ok) throw new Error(`${path}: ${response.status}`);
      return await response.json();
    }
    async function runAction(action, source) {
      const status = document.getElementById("action-status");
      status.hidden = false;
      status.textContent = "Running action...";
      try {
        const result = await actionRequest(action, source);
        applyActionResult(action, result);
        state.lastAction = {action, result, at: new Date().toLocaleString()};
        await refresh();
      } catch (err) {
        status.textContent = err.message;
        status.className = "panel action-status error";
      }
    }
    function applyActionResult(action, result) {
      if (action === "documents-list-notes") state.data.documentsNotes = result;
      if (action === "documents-search") state.data.documentsSearch = result;
      if (action === "documents-capture-knowledge") state.data.knowledgeCapturePlan = result;
      if (action === "record-remote-testing-profile" || action === "request-remote-testing-lease") state.data.remoteTesting = result.status || result;
      if (action === "enqueue-remote-test-job" || action === "collect-remote-test-results") state.data.remoteTesting = result.status || state.data.remoteTesting;
    }
    async function actionRequest(action, source) {
      if (action === "discover-physical") return await postJson("/physical/discover", {});
      if (action === "discover-storage") return await postJson("/physical/discover-storage", {});
      if (action === "discover-listeners") return await postJson("/virtual/discover-listeners", {});
      if (action === "stage-virtual-target-setup-batch") return await stageVirtualTargetSetupBatch();
      if (action === "record-virtual-target-setup-result") return await recordVirtualTargetSetupResult();
      if (action === "execute-virtual-target-setup") return await executeVirtualTargetSetup();
      if (action === "record-virtual-runtime") return await recordVirtualRuntime();
      if (action === "execute-virtual-lifecycle") return await executeVirtualLifecycle();
      if (action === "stage-virtual-snapshot-request") return await stageVirtualSnapshotRequest();
      if (action === "approve-virtual-snapshot-request") return await approveVirtualSnapshotRequest();
      if (action === "execute-virtual-snapshot-request") return await executeVirtualSnapshotRequest();
      if (action === "stage-virtual-restore-request") return await stageVirtualRestoreRequest();
      if (action === "approve-virtual-restore-request") return await approveVirtualRestoreRequest();
      if (action === "execute-virtual-restore-request") return await executeVirtualRestoreRequest();
      if (action === "stage-virtual-destroy-request") return await stageVirtualDestroyRequest();
      if (action === "approve-virtual-destroy-request") return await approveVirtualDestroyRequest();
      if (action === "execute-virtual-destroy-request") return await executeVirtualDestroyRequest();
      if (action === "stage-image-scan") return await stageImageScanRequest();
      if (action === "approve-image-scan") return await approveImageScanRequest();
      if (action === "execute-image-scan") return await executeImageScanRequest();
      if (action === "record-backup-job") return await recordBackupJob();
      if (action === "record-restore-test") return await recordRestoreTest();
      if (action === "stage-backup-execution-request") return await stageBackupExecutionRequest();
      if (action === "approve-backup-execution-request") return await approveBackupExecutionRequest();
      if (action === "execute-backup-execution-request") return await executeBackupExecutionRequest();
      if (action === "capture-storage-growth-snapshot") return await captureStorageGrowthSnapshot();
      if (action === "stage-restore-execution-request") return await stageRestoreExecutionRequest();
      if (action === "approve-restore-execution-request") return await approveRestoreExecutionRequest();
      if (action === "execute-restore-execution-request") return await executeRestoreExecutionRequest();
      if (action === "stage-backup-cleanup-request") return await stageBackupCleanupRequest();
      if (action === "approve-backup-cleanup-request") return await approveBackupCleanupRequest();
      if (action === "execute-backup-cleanup-request") return await executeBackupCleanupRequest();
      if (action === "register-resource") return await registerResource();
      if (action === "request-claim") return await requestClaim();
      if (action === "approve-claim") return await approveClaim();
      if (action === "activate-claim") return await activateClaim();
      if (action === "release-claim") return await releaseClaim();
      if (action === "request-claim-cleanup") return await requestClaimCleanup();
      if (action === "approve-claim-cleanup") return await approveClaimCleanup();
      if (action === "execute-claim-cleanup") return await executeClaimCleanup();
      if (action === "discover-user-services") return await postJson("/services/discover-user", {});
      if (action === "discover-agent-sessions") return await discoverAgentSessions();
      if (action === "resume-agent-sessions") return await resumeAgentSession();
      if (action === "checkpoint-agent") return await checkpointAgent();
      if (action === "handoff-agent") return await changePrimaryAgent("/agent-handoffs", "manual handoff");
      if (action === "failover-agent") return await controlledFailover();
      if (action === "recover-agent-failover") return await recoverAgentFailover();
      if (action === "discover-codex-threads") return await postJson("/codex-projects/discover-threads", {});
      if (action === "record-usage-limit") return await recordUsageLimit();
      if (action === "send-crew-message") return await sendCrewMessage(source.dataset.role, source);
      if (action === "dispatch-crew-messages") return await dispatchCrewMessages(source?.dataset?.role || "");
      if (action === "documents-list-notes") return await listDocumentsNotes();
      if (action === "documents-search") return await searchDocuments();
      if (action === "documents-write-note") return await writeDocumentNote();
      if (action === "documents-capture-knowledge") return await captureKnowledge();
      if (action === "request-usage-continuation") return await requestUsageContinuation();
      if (action === "dispatch-usage-continuations") return await dispatchUsageContinuations();
      if (action === "record-remote-testing-profile") return await recordRemoteTestingProfile();
      if (action === "request-remote-testing-lease") return await requestRemoteTestingLease();
      if (action === "enqueue-remote-test-job") return await enqueueRemoteTestJob();
      if (action === "collect-remote-test-results") return await collectRemoteTestResults();
      if (action === "plan-package-updates") return await postJson("/maintenance/package-update-plans", {});
      if (action === "plan-firmware-updates") return await postJson("/maintenance/firmware-update-plans", {});
      if (action === "run-package-maintenance-cycle") return await postJson("/maintenance/package-maintenance-cycle", {});
      if (action === "refresh-advisories") return await refreshAdvisories();
      if (action === "record-maintenance-schedule") return await recordMaintenanceSchedule();
      if (action === "plan-admin-change") return await planAdminChange();
      if (action === "approve-admin-change") return await approveAdminChange();
      if (action === "approve-and-execute-admin-change") return await approveAndExecuteAdminChange();
      if (action === "cancel-admin-change") return await cancelAdminChange();
      if (action === "execute-admin-change") return await executeAdminChange();
      if (action === "request-admin-adapter-enablement") return await requestAdminAdapterEnablement();
      if (action === "approve-admin-adapter-enablement") return await approveAdminAdapterEnablement();
      if (action === "build-policy-profile") return await buildPolicyProfile();
      if (action === "request-policy-warning") return await requestPolicyWarning();
      if (action === "approve-policy-warning") return await approvePolicyWarning();
      if (action === "request-admin-archive") return await requestAdminArchive();
      if (action === "approve-admin-archive") return await approveAdminArchive();
      if (action === "archive-admin-history") return await archiveAdminHistory();
      if (action === "request-admin-restore") return await requestAdminRestore();
      if (action === "approve-admin-restore") return await approveAdminRestore();
      if (action === "unarchive-admin-history") return await unarchiveAdminHistory();
      if (action === "run-health-probes") return await postJson("/health/probes/run", {retention_per_target: 5});
      if (action === "register-health-target") return await registerHealthTarget();
      if (action === "stage-journal-access-request") return await stageJournalAccessRequest();
      if (action === "execute-journal-access-request") return await executeJournalAccessRequest();
      if (action === "capture-metric-history") return await captureMetricHistory();
      if (action === "inspect-host") return await postJson("/host/inspect", {});
      if (action === "advance-odo-security") return await postJson("/host/security/advance", {requested_by: "odo"});
      if (action === "plan-listener-queue-remediations") return await postJson("/host/security/listener-review-queue/remediation-plans", {requested_by: "odo"});
      if (action === "plan-host-security-remediation") return await planHostSecurityRemediation();
      if (action === "record-source-review") return await recordSourceReview();
      if (action === "stage-identity-rotation-request") return await stageIdentityRotationRequest();
      if (action === "approve-identity-rotation-request") return await approveIdentityRotationRequest();
      if (action === "execute-identity-rotation-request") return await executeIdentityRotationRequest();
      if (action === "record-operation") return await recordOperation();
      if (action === "transition-operation") return await transitionOperation();
      if (action === "stage-operation-workflow") return await stageOperationWorkflow();
      if (action === "plan-source-block") return await planSourceBlock();
      if (action === "stage-firewall-policy-enforcement") return await stageFirewallPolicyEnforcement();
      if (action === "execute-firewall-change") return await executeFirewallChange();
      if (action === "prepare-ids-review-package") return await prepareIdsReviewPackage();
      if (action === "export-ids-review-prompt") return await exportIdsReviewPrompt();
      if (action === "dispatch-ids-review-package") return await dispatchIdsReviewPackage();
      if (action === "record-ids-review-result") return await recordIdsReviewResult();
      throw new Error(`unsupported action: ${action}`);
    }
    async function discoverAgentSessions() {
      return await postJson("/agent-sessions/discover", {
        provider_id: value("agent-provider-id"),
        instance_id: value("agent-instance-id")
      });
    }
    async function resumeAgentSession() {
      return await postJson("/agent-recovery", {
        session_id: value("agent-session-id"),
        initiated_by: value("agent-initiated-by") || "operator"
      });
    }
    async function checkpointAgent() {
      return await postJson("/agent-checkpoints", {
        instance_id: value("agent-instance-id")
      });
    }
    async function changePrimaryAgent(path, operation) {
      const approval_id = value("agent-approval-id");
      if (!approval_id) throw new Error("approval_id is required");
      if (!window.confirm(`Confirm ${operation} using approval ${approval_id}?`)) {
        throw new Error(`${operation} cancelled by operator`);
      }
      return await postJson(path, validatedTransferPayload(
        value("agent-instance-id"),
        value("agent-incoming-provider-id"),
        value("agent-initiated-by"),
        approval_id
      ));
    }
    async function controlledFailover() {
      const instance_id = value("agent-instance-id");
      const selectedProvider = value("agent-incoming-provider-id");
      const evaluation = await postJson("/agent-failover/evaluate", {instance_id});
      const decision = evaluation.decision || {};
      const blockers = decision.blockers || [];
      const display = document.getElementById("agent-failover-blockers");
      if (display) display.textContent = blockers.length
        ? blockers.join("; ")
        : `Allowed candidate: ${decision.incoming_provider_id || "none"}`;
      if (!decision.allowed) throw new Error(blockers.join("; ") || "failover is blocked");
      if (decision.instance_id !== instance_id || decision.incoming_provider_id !== selectedProvider) {
        throw new Error("fresh failover decision does not match the selected approved fallback");
      }
      const approval_id = value("agent-approval-id");
      if (!approval_id) throw new Error("approval_id is required");
      if (!window.confirm(`Confirm controlled failover using approval ${approval_id}?`)) {
        throw new Error("controlled failover cancelled by operator");
      }
      return await postJson("/agent-failover", {
        instance_id,
        decision_id: decision.id,
        initiated_by: value("agent-initiated-by"),
        approval_id
      });
    }
    async function recoverAgentFailover() {
      const execution = (state.data.agentFailoverExecutions?.executions || []).find(
        (item) => ["reserved", "draining", "blocked_preimport", "recovering"].includes(item.recovery_state)
      );
      if (!execution) throw new Error("no recoverable failover execution");
      const approval_id = value("agent-approval-id");
      if (!approval_id) throw new Error("approval_id is required");
      if (!window.confirm(`Confirm recovery ${execution.id} using approval ${approval_id}?`)) {
        throw new Error("failover recovery cancelled by operator");
      }
      return await postJson("/agent-failover/recover", {
        execution_id: execution.id,
        initiated_by: value("agent-initiated-by"),
        approval_id
      });
    }
    async function registerResource() {
      const resourceId = document.getElementById("resource-id").value.trim();
      const name = document.getElementById("resource-name").value.trim();
      const resourceType = document.getElementById("resource-type").value;
      const ownerDomain = document.getElementById("resource-owner").value;
      const riskLevel = document.getElementById("resource-risk").value;
      const identifiersText = document.getElementById("resource-identifiers").value.trim();
      const payload = {resource_id: resourceId, name, resource_type: resourceType, owner_domain: ownerDomain, risk_level: riskLevel};
      if (identifiersText) payload.identifiers = JSON.parse(identifiersText);
      return await postJson("/resources", payload);
    }
    async function recordBackupJob() {
      return await postJson("/storage/backup-jobs", {
        job_id: value("backup-job-id"),
        target: value("backup-target"),
        schedule: value("backup-schedule") || "manual",
        retention: value("backup-retention") || "operator-defined",
        requested_by: value("backup-requested-by") || "kira",
        risk_level: value("backup-risk") || "medium",
        status: value("backup-status") || "staged",
        notes: value("backup-notes")
      });
    }
    async function recordRestoreTest() {
      return await postJson("/storage/restore-tests", {
        test_id: value("restore-test-id"),
        job_id: value("restore-job-id"),
        restore_point: value("restore-point"),
        status: value("restore-status") || "planned",
        validated_by: value("restore-validated-by") || "kira",
        notes: value("restore-notes")
      });
    }
    async function stageBackupExecutionRequest() {
      return await postJson("/storage/backup-execution-requests", {
        source_path: value("backup-exec-source-path"),
        backup_name: value("backup-exec-backup-name"),
        requested_by: value("backup-exec-requested-by") || "kira",
        reason: value("backup-exec-reason") || "stage approved local backup execution"
      });
    }
    async function approveBackupExecutionRequest() {
      return await postJson("/storage/backup-execution-requests/approve", {
        request_id: value("backup-exec-request-id"),
        approved_by: value("backup-exec-approved-by") || "kira"
      });
    }
    async function executeBackupExecutionRequest() {
      return await postJson("/storage/backup-execution-requests/execute", {
        request_id: value("backup-exec-request-id"),
        executed_by: value("backup-exec-executed-by") || "kira"
      });
    }
    async function captureStorageGrowthSnapshot() {
      return await postJson("/storage/growth-snapshots/capture", {
        snapshot_id: value("storage-growth-snapshot-id"),
        requested_by: value("storage-growth-requested-by") || "kira",
        notes: value("storage-growth-notes"),
        max_snapshots: Number(value("storage-growth-retention") || 250)
      });
    }
    async function stageRestoreExecutionRequest() {
      return await postJson("/storage/restore-execution-requests", {
        backup_path: value("restore-exec-backup-path"),
        restore_target: value("restore-exec-restore-target"),
        requested_by: value("restore-exec-requested-by") || "kira",
        reason: value("restore-exec-reason") || "stage approved local restore execution"
      });
    }
    async function approveRestoreExecutionRequest() {
      return await postJson("/storage/restore-execution-requests/approve", {
        request_id: value("restore-exec-request-id"),
        approved_by: value("restore-exec-approved-by") || "kira"
      });
    }
    async function executeRestoreExecutionRequest() {
      return await postJson("/storage/restore-execution-requests/execute", {
        request_id: value("restore-exec-request-id"),
        executed_by: value("restore-exec-executed-by") || "kira"
      });
    }
    async function stageBackupCleanupRequest() {
      return await postJson("/storage/cleanup-requests", {
        path: value("backup-cleanup-path"),
        requested_by: value("backup-cleanup-requested-by") || "kira",
        reason: value("backup-cleanup-reason") || "review generated storage cleanup candidate"
      });
    }
    async function approveBackupCleanupRequest() {
      return await postJson("/storage/cleanup-requests/approve", {
        request_id: value("backup-cleanup-request-id"),
        approved_by: value("backup-cleanup-approved-by") || "kira"
      });
    }
    async function executeBackupCleanupRequest() {
      return await postJson("/storage/cleanup-requests/execute", {
        request_id: value("backup-cleanup-request-id"),
        executed_by: value("backup-cleanup-executed-by") || "kira"
      });
    }
    async function stageVirtualTargetSetupBatch() {
      return await postJson("/virtual/target-setup-requests", {
        requested_by: value("virtual-target-setup-requested-by") || "dax",
        scope: value("virtual-target-setup-scope") || "all",
        reason: value("virtual-target-setup-reason") || "prepare approved disposable real-provider targets for Dax lifecycle development"
      });
    }
    async function recordVirtualTargetSetupResult() {
      return await postJson("/virtual/target-setup-requests/result", {
        provider: value("virtual-target-result-provider") || "docker",
        status: value("virtual-target-result-status") || "completed",
        executed_by: value("virtual-target-result-executed-by") || "dax",
        evidence: value("virtual-target-result-evidence"),
        next_step: value("virtual-target-result-next-step")
      });
    }
    async function executeVirtualTargetSetup() {
      return await postJson("/virtual/target-setup-requests/execute", {
        provider: value("virtual-target-execute-provider") || "docker",
        executed_by: value("virtual-target-execute-executed-by") || "dax",
        approved_by: value("virtual-target-execute-approved-by") || "sisko"
      });
    }
    async function recordVirtualRuntime() {
      const ports = value("virtual-ports")
        .split(/[,\\n]/)
        .map((item) => item.trim())
        .filter(Boolean)
        .map(Number);
      return await postJson("/virtual/runtime-records", {
        resource_id: value("virtual-resource-id"),
        kind: value("virtual-kind") || "vm",
        state: value("virtual-state") || "observed",
        adapter: value("virtual-adapter") || "manual",
        ports,
        snapshot_hint: value("virtual-snapshot-hint"),
        notes: value("virtual-notes")
      });
    }
    async function executeVirtualLifecycle() {
      return await postJson("/virtual/lifecycle/execute", {
        resource_id: value("virtual-lifecycle-resource-id"),
        action: value("virtual-lifecycle-action") || "inspect",
        executed_by: value("virtual-lifecycle-executed-by") || "dax",
        provider: value("virtual-lifecycle-provider")
      });
    }
    async function stageVirtualSnapshotRequest() {
      return await postJson("/virtual/snapshot-requests", {
        resource_id: value("snapshot-resource-id"),
        requested_by: value("snapshot-requested-by") || "dax",
        reason: value("snapshot-reason") || "stage virtual snapshot before maintenance",
        snapshot_name: value("snapshot-name")
      });
    }
    async function approveVirtualSnapshotRequest() {
      return await postJson("/virtual/snapshot-requests/approve", {
        request_id: value("snapshot-request-id"),
        approved_by: value("snapshot-approved-by") || "sisko"
      });
    }
    async function executeVirtualSnapshotRequest() {
      return await postJson("/virtual/snapshot-requests/execute", {
        request_id: value("snapshot-request-id"),
        executed_by: value("snapshot-executed-by") || "dax",
        provider: value("snapshot-provider") || "local_fixture"
      });
    }
    async function stageVirtualRestoreRequest() {
      return await postJson("/virtual/restore-requests", {
        resource_id: value("restore-virtual-resource-id"),
        restore_point: value("restore-virtual-point"),
        requested_by: value("restore-virtual-requested-by") || "dax",
        reason: value("restore-virtual-reason") || "stage virtual restore after failed change"
      });
    }
    async function approveVirtualRestoreRequest() {
      return await postJson("/virtual/restore-requests/approve", {
        request_id: value("restore-virtual-request-id"),
        approved_by: value("restore-virtual-approved-by") || "sisko"
      });
    }
    async function executeVirtualRestoreRequest() {
      return await postJson("/virtual/restore-requests/execute", {
        request_id: value("restore-virtual-request-id"),
        executed_by: value("restore-virtual-executed-by") || "dax",
        provider: value("restore-virtual-provider") || "local_fixture"
      });
    }
    async function stageVirtualDestroyRequest() {
      return await postJson("/virtual/destroy-requests", {
        resource_id: value("destroy-virtual-resource-id"),
        requested_by: value("destroy-virtual-requested-by") || "dax",
        reason: value("destroy-virtual-reason") || "stage virtual destroy after disposable target is no longer needed"
      });
    }
    async function approveVirtualDestroyRequest() {
      return await postJson("/virtual/destroy-requests/approve", {
        request_id: value("destroy-virtual-request-id"),
        approved_by: value("destroy-virtual-approved-by") || "sisko"
      });
    }
    async function executeVirtualDestroyRequest() {
      return await postJson("/virtual/destroy-requests/execute", {
        request_id: value("destroy-virtual-request-id"),
        executed_by: value("destroy-virtual-executed-by") || "dax",
        provider: value("destroy-virtual-provider") || "local_fixture"
      });
    }
    async function stageImageScanRequest() {
      return await postJson("/virtual/image-scans", {
        image: value("image-scan-image"),
        provider: value("image-scan-provider") || "docker",
        scanner: value("image-scan-scanner") || "trivy",
        requested_by: value("image-scan-requested-by") || "dax",
        reason: value("image-scan-reason") || "scan container image before production use"
      });
    }
    async function approveImageScanRequest() {
      return await postJson("/virtual/image-scans/approve", {
        request_id: value("image-scan-request-id"),
        approved_by: value("image-scan-approved-by") || "sisko"
      });
    }
    async function executeImageScanRequest() {
      return await postJson("/virtual/image-scans/execute", {
        request_id: value("image-scan-request-id"),
        executed_by: value("image-scan-executed-by") || "dax"
      });
    }
    async function requestClaim() {
      const payload = {
        claim_id: value("claim-id"),
        resource_id: value("claim-resource-id"),
        claim_type: value("claim-type"),
        owner_thread: value("claim-owner-thread"),
        owner_role: value("claim-owner-role"),
        intent: value("claim-intent"),
        requested_action: value("claim-action"),
        risk_level: value("claim-risk")
      };
      const port = value("claim-port");
      if (port) payload.ports = [Number(port)];
      const expiresAt = value("claim-expires-at");
      if (expiresAt) payload.expires_at = expiresAt;
      const releaseCondition = value("claim-release-condition");
      if (releaseCondition) payload.release_condition = releaseCondition;
      return await postJson("/claims/request", payload);
    }
    async function approveClaim() {
      return await postJson("/claims/approve", {
        approval_id: value("claim-approval-id"),
        decided_by: value("claim-decided-by")
      });
    }
    async function activateClaim() {
      const payload = {claim_id: value("claim-activate-id")};
      const approvalId = value("claim-activate-approval-id");
      if (approvalId) payload.approval_id = approvalId;
      return await postJson("/claims/activate", payload);
    }
    async function releaseClaim() {
      const payload = {claim_id: value("claim-release-id")};
      const releasedBy = value("claim-released-by");
      const reason = value("claim-release-reason");
      if (releasedBy) payload.released_by = releasedBy;
      if (reason) payload.reason = reason;
      return await postJson("/claims/release", payload);
    }
    async function requestClaimCleanup() {
      return await postJson("/claims/cleanup-requests", {
        claim_id: value("cleanup-claim-id"),
        requested_by: value("cleanup-requested-by")
      });
    }
    async function approveClaimCleanup() {
      return await postJson("/claims/cleanup-requests/approve", {
        approval_id: value("cleanup-approval-id"),
        approved_by: value("cleanup-approved-by")
      });
    }
    async function executeClaimCleanup() {
      return await postJson("/claims/cleanup-requests/execute", {
        approval_id: value("cleanup-execute-approval-id"),
        executed_by: value("cleanup-executed-by")
      });
    }
    async function planAdminChange() {
      const payload = {
        plan_id: value("admin-plan-id"),
        kind: value("admin-kind"),
        target: value("admin-target"),
        reason: value("admin-reason"),
        current_state: value("admin-current-state") || "unknown"
      };
      const packageName = value("admin-package");
      if (packageName) payload.packages = [packageName];
      const port = value("admin-port");
      if (port) payload.port = Number(port);
      const composeProjectDirectory = value("admin-compose-project-directory");
      if (composeProjectDirectory) payload.compose_project_directory = composeProjectDirectory;
      const composeEnv = splitList(value("admin-compose-env"));
      if (composeEnv.length) payload.compose_env = composeEnv;
      const composeRollbackEnv = splitList(value("admin-compose-rollback-env"));
      if (composeRollbackEnv.length) payload.compose_rollback_env = composeRollbackEnv;
      const composeExtraFiles = splitList(value("admin-compose-extra-files"));
      if (composeExtraFiles.length) payload.compose_extra_file = composeExtraFiles;
      const composeScanImages = splitList(value("admin-compose-scan-images"));
      if (composeScanImages.length) payload.compose_scan_image = composeScanImages;
      const composeResidualScanFindings = splitList(value("admin-compose-residual-scan-findings"));
      if (composeResidualScanFindings.length) payload.compose_residual_scan_finding = composeResidualScanFindings;
      const healthUrl = value("admin-health-url");
      if (healthUrl) payload.health_url = healthUrl;
      const backupLabel = value("admin-backup-label");
      if (backupLabel) payload.backup_label = backupLabel;
      const mountPath = value("admin-mount-path");
      if (mountPath) payload.mount_path = mountPath;
      const credentialFile = value("admin-credential-file");
      if (credentialFile) payload.credential_file = credentialFile;
      const filesystemType = value("admin-filesystem-type");
      if (filesystemType) payload.filesystem_type = filesystemType;
      if (value("admin-use-firewalld") === "true") payload.use_firewalld = true;
      return await postJson("/admin/plans", payload);
    }
    async function recordMaintenanceSchedule() {
      const metadataText = value("maintenance-schedule-metadata");
      const payload = {
        schedule_id: value("maintenance-schedule-id"),
        target: value("maintenance-schedule-target"),
        recurrence: value("maintenance-schedule-recurrence"),
        window: value("maintenance-schedule-window"),
        timezone: value("maintenance-schedule-timezone") || "UTC",
        blackout: value("maintenance-schedule-blackout"),
        validation: value("maintenance-schedule-validation"),
        rollback: value("maintenance-schedule-rollback"),
        status: value("maintenance-schedule-status"),
        owner_domain: value("maintenance-schedule-owner") || "obrien",
        risk_level: value("maintenance-schedule-risk") || "medium",
        notes: value("maintenance-schedule-notes")
      };
      if (metadataText) payload.metadata = JSON.parse(metadataText);
      return await postJson("/maintenance/schedules", payload);
    }
    async function stageJournalAccessRequest() {
      return await postJson("/health/journal-access-requests", {
        resource_id: value("journal-resource-id"),
        unit: value("journal-unit"),
        requested_by: value("journal-requested-by") || "julian",
        reason: value("journal-reason") || "system journal access needed for service diagnosis"
      });
    }
    async function executeJournalAccessRequest() {
      return await postJson("/health/journal-access-requests/execute", {
        record_id: value("journal-execute-record-id"),
        executed_by: value("journal-execute-by") || "julian",
        line_limit: Number(value("journal-execute-lines") || 50),
        since: value("journal-execute-since") || "24 hours ago"
      });
    }
    async function captureMetricHistory() {
      return await postJson("/observability/metric-history/capture", {
        snapshot_id: value("metric-history-id"),
        requested_by: value("metric-history-requested-by") || "julian",
        notes: value("metric-history-notes"),
        max_snapshots: Number(value("metric-history-retention") || 250)
      });
    }
    async function refreshAdvisories() {
      const packages = value("advisory-packages")
        .split(/[,\\n]/)
        .map((item) => item.trim())
        .filter(Boolean);
      return await postJson("/maintenance/advisories/refresh", {
        packages,
        source: value("advisory-source") || "nvd",
        max_results_per_package: Number(value("advisory-max-results") || 5),
        requested_by: value("advisory-requested-by") || "obrien",
        dry_run: document.getElementById("advisory-dry-run")?.checked || false
      });
    }
    async function approveAdminChange() {
      return await postJson("/admin/approve", {
        plan_id: value("admin-approval-plan-id"),
        approved_by: value("admin-approved-by")
      });
    }
    async function approveAndExecuteAdminChange() {
      const approval = await approveAdminChange();
      try {
        return {
          status: "approved_and_execution_requested",
          approval,
          execution: await executeAdminChange()
        };
      } catch (error) {
        return {
          status: "approved_execution_blocked",
          approval,
          execution_error: error.message
        };
      }
    }
    async function cancelAdminChange() {
      return await postJson("/admin/cancel", {
        plan_id: value("admin-cancel-plan-id"),
        canceled_by: value("admin-canceled-by"),
        reason: value("admin-cancel-reason")
      });
    }
    async function executeAdminChange() {
      return await postJson("/admin/execute", {
        plan_id: value("admin-execute-plan-id")
      });
    }
    async function requestAdminAdapterEnablement() {
      return await postJson("/admin/adapter-enablement-requests", {
        kind: value("admin-adapter-kind"),
        requested_by: value("admin-adapter-requested-by") || "sisko"
      });
    }
    async function approveAdminAdapterEnablement() {
      return await postJson("/admin/adapter-enablement-requests/approve", {
        approval_id: value("admin-adapter-approval-id"),
        approved_by: value("admin-adapter-approved-by") || "sisko"
      });
    }
    async function buildPolicyProfile() {
      const answers = {
        name: value("policy-profile-name") || "custom",
        description: value("policy-profile-description") || "Customized Overseer policy profile."
      };
      ((state.data.policyHelper || {}).questions || []).forEach((question) => {
        answers[question.id] = typedPolicyAnswer(question, value(`policy-answer-${question.id}`));
      });
      return await postJson("/admin/policy-customization-helper/profile", {answers});
    }
    async function requestPolicyWarning() {
      return await postJson("/admin/policy-warning-requests", {
        plan_id: value("policy-warning-plan-id"),
        check_id: value("policy-warning-check-id"),
        requested_by: value("policy-warning-requested-by") || "sisko"
      });
    }
    async function approvePolicyWarning() {
      return await postJson("/admin/policy-warning-requests/approve", {
        approval_id: value("policy-warning-approval-id"),
        approved_by: value("policy-warning-approved-by") || "human"
      });
    }
    async function requestAdminArchive() {
      const payload = {requested_by: value("admin-archive-requested-by") || "sisko"};
      const planId = value("admin-archive-plan-id");
      if (planId) payload.plan_id = planId;
      return await postJson("/admin/history-archive-requests", payload);
    }
    async function approveAdminArchive() {
      return await postJson("/admin/history-archive-requests/approve", {
        approval_id: value("admin-archive-approval-id"),
        approved_by: value("admin-archive-approved-by") || "sisko"
      });
    }
    async function archiveAdminHistory() {
      const payload = {
        approval_id: value("admin-archive-execute-approval-id"),
        archived_by: value("admin-archived-by") || "sisko"
      };
      const planId = value("admin-archive-execute-plan-id");
      if (planId) payload.plan_id = planId;
      return await postJson("/admin/history-archive", payload);
    }
    async function requestAdminRestore() {
      return await postJson("/admin/history-restore-requests", {
        plan_id: value("admin-restore-plan-id"),
        requested_by: value("admin-restore-requested-by") || "sisko"
      });
    }
    async function approveAdminRestore() {
      return await postJson("/admin/history-restore-requests/approve", {
        approval_id: value("admin-restore-approval-id"),
        approved_by: value("admin-restore-approved-by") || "sisko"
      });
    }
    async function unarchiveAdminHistory() {
      return await postJson("/admin/history-unarchive", {
        plan_id: value("admin-unarchive-plan-id"),
        approval_id: value("admin-unarchive-approval-id"),
        restored_by: value("admin-unarchived-by") || "sisko"
      });
    }
    async function registerHealthTarget() {
      const targetId = document.getElementById("health-target-id").value.trim();
      const resourceId = document.getElementById("health-resource-id").value.trim();
      const name = document.getElementById("health-name").value.trim();
      const probeType = document.getElementById("health-probe-type").value;
      const target = document.getElementById("health-target").value.trim();
      const expectedStatus = document.getElementById("health-expected-status").value.trim();
      const expectedContentType = document.getElementById("health-expected-content-type").value.trim();
      const payload = {target_id: targetId, resource_id: resourceId, name, probe_type: probeType, target};
      if (expectedStatus) payload.expected_status = Number(expectedStatus);
      if (expectedContentType) payload.expected_content_type = expectedContentType;
      return await postJson("/health-targets", payload);
    }
    async function recordUsageLimit() {
      const payload = {
        limit_id: value("usage-limit-id"),
        resource_id: value("usage-resource-id"),
        kind: value("usage-kind"),
        capacity: Number(value("usage-capacity")),
        remaining: Number(value("usage-remaining")),
        window: value("usage-window"),
        confidence: Number(value("usage-confidence") || "1")
      };
      const resetsAt = value("usage-resets-at");
      const observedAt = value("usage-observed-at");
      if (resetsAt) payload.resets_at = resetsAt;
      if (observedAt) payload.observed_at = observedAt;
      return await postJson("/usage-limits", payload);
    }
    async function sendCrewMessage(role, source) {
      const prefix = source.dataset.prefix || rolePrefix(role);
      const payload = {
        owner_domain: role,
        subject: value(`${prefix}-subject`),
        message: value(`${prefix}-message`),
        priority: value(`${prefix}-priority`),
        requested_by: value(`${prefix}-requested-by`) || "operator"
      };
      const resourceId = value(`${prefix}-resource-id`);
      const planId = value(`${prefix}-plan-id`);
      const limitId = value(`${prefix}-limit-id`);
      if (resourceId) payload.related_resource_id = resourceId;
      if (planId) payload.related_plan_id = planId;
      if (limitId) payload.related_limit_id = limitId;
      return await postJson("/crew/messages", payload);
    }
    async function recordOperation() {
      const metadataText = value("op-metadata");
      const payload = {
        record_id: value("op-record-id"),
        kind: value("op-kind"),
        owner_domain: value("op-owner"),
        status: value("op-status"),
        subject: value("op-subject"),
        summary: value("op-summary"),
        severity: value("op-severity"),
        next_step: value("op-next-step")
      };
      const resourceId = value("op-resource-id");
      const evidenceIds = value("op-evidence-ids");
      if (resourceId) payload.resource_id = resourceId;
      if (evidenceIds) payload.evidence_ids = evidenceIds.split(",").map((item) => item.trim()).filter(Boolean);
      if (metadataText) payload.metadata = JSON.parse(metadataText);
      return await postJson("/operations/records", payload);
    }
    async function transitionOperation() {
      const payload = {
        record_id: value("op-transition-record-id"),
        status: value("op-transition-status"),
        updated_by: value("op-transition-by") || "sisko"
      };
      const nextStep = value("op-transition-next-step");
      const note = value("op-transition-note");
      if (nextStep) payload.next_step = nextStep;
      if (note) payload.summary_note = note;
      return await postJson("/operations/records/transition", payload);
    }
    async function stageOperationWorkflow() {
      const payload = {
        template_id: value("op-workflow-template-id"),
        requested_by: value("op-workflow-requested-by") || "sisko"
      };
      const recordId = value("op-workflow-record-id");
      const resourceId = value("op-workflow-resource-id");
      if (recordId) payload.record_id = recordId;
      if (resourceId) payload.resource_id = resourceId;
      return await postJson("/operations/workflows/stage", payload);
    }
    async function dispatchCrewMessages(role) {
      const payload = {dispatched_by: "sisko"};
      if (role) payload.owner_domain = role;
      return await postJson("/crew/dispatch", payload);
    }
    async function listDocumentsNotes() {
      state.documentsFolder = value("documents-folder") || "Overseer";
      return await getJson(documentsNotesPath());
    }
    async function searchDocuments() {
      state.documentsQuery = value("documents-query") || "Overseer";
      return await postJson("/documents/search", {
        query: state.documentsQuery,
        context_length: Number(value("documents-context-length") || "100")
      });
    }
    async function writeDocumentNote() {
      return await postJson("/documents/notes", {
        path: value("documents-note-path"),
        mode: value("documents-note-mode"),
        content: value("documents-note-content")
      });
    }
    async function captureKnowledge() {
      return await postJson("/documents/knowledge-capture", {
        kinds: ["crew", "audit"],
        limit: Number(value("knowledge-capture-limit") || "12"),
        dry_run: false
      });
    }
    async function requestUsageContinuation() {
      const payload = {
        request_id: value("usage-request-id"),
        limit_id: value("usage-request-limit-id"),
        resource_id: value("usage-request-resource-id"),
        owner_thread: value("usage-owner-thread"),
        requested_units: Number(value("usage-requested-units")),
        intent: value("usage-intent"),
        risk_level: value("usage-risk"),
        requested_by: value("usage-requested-by") || "quark"
      };
      const earliestStart = value("usage-earliest-start");
      const deadline = value("usage-deadline");
      if (earliestStart) payload.earliest_start = earliestStart;
      if (deadline) payload.deadline = deadline;
      return await postJson("/usage/continuation-requests", payload);
    }
    async function dispatchUsageContinuations() {
      return await postJson("/usage/continuation-dispatches", {
        dispatched_by: value("usage-dispatched-by") || "quark",
        resume_codex_projects: document.getElementById("usage-resume-codex-projects").checked
      });
    }
    async function recordRemoteTestingProfile() {
      return await postJson("/usage/remote-testing/profiles", {
        profile_id: value("remote-profile-id") || "remote-testing.tank-msi",
        display_name: value("remote-display-name") || "Tank on MSI remote testing queue",
        worker_hint: value("remote-worker-hint") || "overseer-msi-test-agent",
        base_url: value("remote-base-url") || "http://127.0.0.1:8766",
        ui_path: value("remote-ui-path") || "/Overseer/ui",
        gateway_path: value("remote-gateway-path") || "/Overseer",
        token_source: value("remote-token-source") || "state/api-token",
        remote_host: value("remote-host") || "god@10.50.0.100",
        recorded_by: value("remote-recorded-by") || "quark"
      });
    }
    async function requestRemoteTestingLease() {
      return await postJson("/usage/remote-testing/leases", {
        lease_id: value("remote-lease-id") || "lease.overseer.tank-smoke",
        project: value("remote-project") || "Overseer",
        purpose: value("remote-purpose") || "run protected-gateway regression without human relay",
        requested_by: value("remote-requested-by") || "quark",
        job_types: value("remote-job-types").split(",").map((item) => item.trim()).filter(Boolean),
        ttl_minutes: Number(value("remote-ttl-minutes") || "120"),
        priority: value("remote-priority") || "normal",
        profile_id: value("remote-profile-id") || "remote-testing.tank-msi"
      });
    }
    async function enqueueRemoteTestJob() {
      return await postJson("/usage/remote-testing/jobs", {
        lease_id: value("remote-job-lease-id") || value("remote-lease-id"),
        job_type: value("remote-job-type") || "ping",
        requested_by: value("remote-requested-by") || "quark",
        project: value("remote-project") || "Overseer",
        params: JSON.parse(value("remote-job-params") || "{}"),
        base_url: value("remote-base-url") || "http://127.0.0.1:8766",
        ui_path: value("remote-ui-path") || "/Overseer/ui",
        gateway_path: value("remote-gateway-path") || "/Overseer",
        token_source: value("remote-token-source") || "state/api-token"
      });
    }
    async function collectRemoteTestResults() {
      return await postJson("/usage/remote-testing/results", {
        lease_id: value("remote-result-lease-id") || value("remote-lease-id"),
        job_id: value("remote-result-job-id")
      });
    }
    async function planHostSecurityRemediation() {
      const payload = {
        listener: value("security-listener"),
        action: value("security-remediation-action"),
        reason: value("security-remediation-reason")
      };
      const planId = value("security-plan-id");
      const snapshotId = value("security-snapshot-id");
      if (planId) payload.plan_id = planId;
      if (snapshotId) payload.snapshot_id = snapshotId;
      return await postJson("/host/security/remediations/plans", payload);
    }
    async function recordSourceReview() {
      const payload = {
        remote_address: value("source-remote-address"),
        listener: value("source-listener"),
        disposition: value("source-disposition"),
        rationale: value("source-rationale"),
        reviewed_by: value("source-reviewed-by") || "odo"
      };
      const reviewId = value("source-review-id");
      const snapshotId = value("source-snapshot-id");
      if (reviewId) payload.review_id = reviewId;
      if (snapshotId) payload.snapshot_id = snapshotId;
      return await postJson("/host/security/source-reviews", payload);
    }
    async function planSourceBlock() {
      const payload = {
        review_id: value("source-block-review-id"),
        action: value("source-block-action"),
        reason: value("source-block-reason")
      };
      const planId = value("source-block-plan-id");
      if (planId) payload.plan_id = planId;
      return await postJson("/host/security/source-reviews/block-plans", payload);
    }
    async function stageFirewallPolicyEnforcement() {
      const payload = {
        rule_index: Number(value("firewall-rule-index") || 0),
        requested_by: value("firewall-requested-by") || "odo_firewall",
        reason: value("firewall-enforcement-reason") || undefined
      };
      const planId = value("firewall-plan-id");
      if (planId) payload.plan_id = planId;
      return await postJson("/host/security/firewall-policy/enforcement-plans", payload);
    }
    async function executeFirewallChange() {
      return await postJson("/host/security/firewall-executions/execute", {
        plan_id: value("firewall-execute-plan-id"),
        executed_by: value("firewall-execute-by") || "odo_firewall",
        mode: value("firewall-execute-mode") || "local_fixture"
      });
    }
    async function stageIdentityRotationRequest() {
      return await postJson("/identity/rotation-requests", {
        subject: value("identity-rotation-subject"),
        subject_type: value("identity-rotation-subject-type") || "secret",
        requested_by: value("identity-rotation-requested-by") || "odo",
        reason: value("identity-rotation-reason") || "stage identity or secret rotation review",
        urgency: value("identity-rotation-urgency") || "medium"
      });
    }
    async function approveIdentityRotationRequest() {
      return await postJson("/identity/rotation-requests/approve", {
        request_id: value("identity-rotation-request-id"),
        approved_by: value("identity-rotation-approved-by") || "sisko"
      });
    }
    async function executeIdentityRotationRequest() {
      return await postJson("/identity/rotation-requests/execute", {
        request_id: value("identity-rotation-request-id"),
        executed_by: value("identity-rotation-executed-by") || "odo",
        mode: value("identity-rotation-execute-mode") || "local_fixture"
      });
    }
    async function prepareIdsReviewPackage() {
      const payload = {
        plan_id: value("ids-plan-id"),
        requested_by: value("ids-requested-by") || "odo_ids"
      };
      const packageId = value("ids-package-id");
      const sourceReviewId = value("ids-source-review-id");
      if (packageId) payload.package_id = packageId;
      if (sourceReviewId) payload.source_review_id = sourceReviewId;
      return await postJson("/host/security/ids-review-packages", payload);
    }
    async function exportIdsReviewPrompt() {
      return await postJson("/host/security/ids-review-packages/prompts", {
        package_id: value("ids-export-package-id")
      });
    }
    async function dispatchIdsReviewPackage() {
      const payload = {
        package_id: value("ids-dispatch-package-id"),
        dispatched_by: value("ids-dispatched-by") || "odo_ids"
      };
      const ownerThread = value("ids-owner-thread");
      if (ownerThread) payload.owner_thread = ownerThread;
      return await postJson("/host/security/ids-review-packages/dispatch", payload);
    }
    async function recordIdsReviewResult() {
      return await postJson("/host/security/ids-review-packages/results", {
        package_id: value("ids-result-package-id"),
        status: value("ids-result-status"),
        advisory_result: value("ids-advisory-result"),
        reviewed_by: value("ids-reviewed-by") || "odo_ids"
      });
    }
    function render() {
      const dashboard = state.data.dashboard || {};
      const overall = dashboard.overall_status || "loading";
      const overallEl = document.getElementById("overall");
      overallEl.textContent = overall.replaceAll("_", " ");
      overallEl.className = `pill ${overallClass(overall)}`;
      renderOverview();
      renderDriver();
      renderAdmin();
      renderAssets();
      renderClaims();
      renderSecurity();
      renderHealth();
      renderUsage();
      renderEzri();
      renderAudit();
      renderActionStatus();
    }
    function renderActionStatus() {
      const status = document.getElementById("action-status");
      if (!state.lastAction) return;
      status.className = "panel action-status good";
      status.hidden = false;
      const result = state.lastAction.result || {};
      const detail = result.count ?? result.targets ?? result.resources ?? result.plans ?? result.status ?? "complete";
      status.innerHTML = `<div class="toolbar"><h3>${safe(labelize(state.lastAction.action))}</h3><span class="pill good">${safe(detail)}</span></div><p class="muted">${safe(state.lastAction.at)}</p>`;
    }
    function renderOverview() {
      const focus = (state.data.dashboard || {}).role_focus || {};
      const attention = (state.data.dashboard || {}).attention || {};
      const runtime = state.data.runtime || {};
      const operations = state.data.operations || {};
      const incidentLifecycle = state.data.incidentLifecycle || {};
      const operationWorkflows = state.data.operationWorkflows || {};
      const templates = operationWorkflows.templates || [];
      const crewSummary = (state.data.crewMessages || {}).summary || {};
      const dispatches = (state.data.crewMessages || {}).recent_dispatches || [];
      document.getElementById("overview").innerHTML = `
        <div class="grid">
          ${stationIntro("Sisko", "Strategic Operations", "Command routing, runtime cadence, and crew dispatch.", ["authorizations", "crew queue", "runtime"])}
          ${metric("Sisko", attention.pending_authorizations, "pending authorizations", "span-3", attention.pending_authorizations ? "warn" : "good", "admin")}
          ${metric("Odo", attention.high_security_findings, "high findings", "span-3", attention.high_security_findings ? "bad" : "good", "security")}
          ${metric("Julian", attention.unhealthy_health_targets, "unhealthy targets", "span-3", attention.unhealthy_health_targets ? "bad" : "good", "health")}
          ${metric("O'Brien", focus.obrien?.executable_plans, "executable plans", "span-3", "", "admin")}
          ${metric("Runtime", runtime.service?.freshness?.status, "heartbeat freshness", "span-3", freshnessTone(runtime.service?.freshness?.status), "health")}
          ${metric("Crew Queue", crewSummary.open, "open requests", "span-3", crewSummary.open ? "warn" : "good", "audit")}
          ${metric("Dispatch Blocks", crewSummary.blocked_dispatches, "blocked dispatches", "span-3", crewSummary.blocked_dispatches ? "warn" : "good", "audit")}
          <div class="section-head"><h3>Command Crew</h3><div class="actions"><span class="pill">${safe((state.data.dashboard || {}).service_name)}</span><button class="action-btn" data-action="dispatch-crew-messages">Dispatch Open</button></div></div>
          ${crew("Sisko", focus.sisko)}
          ${crew("Kira", focus.kira)}
          ${crew("O'Brien", focus.obrien)}
          ${crew("Odo", focus.odo)}
          ${crew("Odo IDS", focus.odo_ids)}
          ${crew("Odo Firewall", focus.odo_firewall)}
          ${crew("Quark", focus.quark)}
          ${crew("Dax", focus.dax)}
          ${crew("Julian", focus.julian)}
          <div class="panel span-12">${table("Recent Crew Dispatches", dispatches, ["occurred_at", "owner_domain", "event_type", "message_id", "reason"], {links: {owner_domain: (row) => domainView(row.owner_domain)}})}</div>
          <div class="panel span-6">${table("Incident Board", operations.incidents || [], ["id", "severity", "owner", "status", "next_step"], {links: {owner: (row) => domainView(row.owner)}})}</div>
          <div class="panel span-6">${table("Risk Register", operations.risk_register || [], ["id", "domain", "risk", "state", "next_review"], {links: {domain: (row) => domainView(row.domain)}})}</div>
          <div class="panel span-12">${table("Incident Lifecycle", incidentLifecycle.items || [], ["id", "kind", "owner_domain", "status", "severity", "next_step"], {links: {owner_domain: (row) => domainView(row.owner_domain)}, fills: {id: (row) => operationFill(row)}, fillView: "overview"})}</div>
          <div class="panel span-6">${table("Incident Sources", incidentLifecycle.health_items || [], ["id", "resource_id", "status", "owner_domain", "next_step"], {links: {owner_domain: (row) => domainView(row.owner_domain)}})}</div>
          <div class="panel span-6">${table("Post Incident Checklist", incidentLifecycle.post_incident_checklist || [], ["step", "owner", "status"], {links: {owner: (row) => domainView(row.owner)}})}</div>
          <div class="panel span-12">${table("Operations Coverage", operations.coverage || [], ["area", "status", "available", "next_gap"])}</div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Stage Operations Workflow</h3><button class="action-btn" data-action="stage-operation-workflow">Stage Workflow</button></div>
            <div class="form-grid">
              <div class="field span-3"><label for="op-workflow-template-id">Template</label><select id="op-workflow-template-id">${operationWorkflowOptions(templates)}</select></div>
              <div class="field span-3"><label for="op-workflow-record-id">Record ID</label><input id="op-workflow-record-id" placeholder="optional"></div>
              <div class="field span-3"><label for="op-workflow-resource-id">Resource</label><input id="op-workflow-resource-id" placeholder="optional"></div>
              <div class="field span-3"><label for="op-workflow-requested-by">Requested By</label><input id="op-workflow-requested-by" value="sisko"></div>
            </div>
            ${table("Workflow Templates", templates, ["id", "kind", "owner_domain", "severity", "next_step"], {links: {owner_domain: (row) => domainView(row.owner_domain)}, fills: {id: (row) => operationWorkflowFill(row)}, fillView: "overview"})}
          </div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Record Operation</h3><button class="action-btn" data-action="record-operation">Record</button></div>
            <div class="form-grid">
              <div class="field span-2"><label for="op-record-id">Record ID</label><input id="op-record-id" value="ops.incident.local"></div>
              <div class="field span-2"><label for="op-kind">Kind</label><select id="op-kind">${operationKindOptions()}</select></div>
              <div class="field span-2"><label for="op-owner">Owner</label><select id="op-owner">${ownerOptions()}</select></div>
              <div class="field span-2"><label for="op-status">Status</label><select id="op-status">${operationStatusOptions()}</select></div>
              <div class="field span-2"><label for="op-severity">Severity</label><select id="op-severity">${riskOptions()}</select></div>
              <div class="field span-2"><label for="op-resource-id">Resource</label><input id="op-resource-id"></div>
              <div class="field span-4"><label for="op-subject">Subject</label><input id="op-subject" value="Track operations workflow"></div>
              <div class="field span-4"><label for="op-evidence-ids">Evidence IDs</label><input id="op-evidence-ids"></div>
              <div class="field span-4"><label for="op-next-step">Next Step</label><input id="op-next-step" value="review and assign"></div>
              <div class="field span-6"><label for="op-summary">Summary</label><textarea id="op-summary">Record the operational workflow and evidence needed.</textarea></div>
              <div class="field span-6"><label for="op-metadata">Metadata</label><textarea id="op-metadata">{}</textarea></div>
            </div>
          </div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Transition Operation</h3><button class="action-btn" data-action="transition-operation">Transition</button></div>
            <div class="form-grid">
              <div class="field span-3"><label for="op-transition-record-id">Record ID</label><input id="op-transition-record-id" value="ops.incident.local"></div>
              <div class="field span-3"><label for="op-transition-status">Status</label><select id="op-transition-status">${operationStatusOptions()}</select></div>
              <div class="field span-3"><label for="op-transition-by">Updated By</label><input id="op-transition-by" value="sisko"></div>
              <div class="field span-3"><label for="op-transition-next-step">Next Step</label><input id="op-transition-next-step" value="verify evidence and continue"></div>
              <div class="field span-12"><label for="op-transition-note">Note</label><input id="op-transition-note" value="Lifecycle state updated from operator review."></div>
            </div>
          </div>
          <div class="panel span-12">${table("Operation Records", (operations.operation_records || {}).items || [], ["id", "kind", "owner_domain", "status", "severity", "next_step"], {links: {owner_domain: (row) => domainView(row.owner_domain)}, fills: {id: (row) => operationFill(row)}, fillView: "overview"})}</div>
          ${officerPanel("sisko", "Command routing", "Coordinate this issue across the crew.")}
        </div>`;
    }
    function renderDriver() {
      // Static action contract for regression/audit tooling:
      // data-action="discover-agent-sessions"
      // data-action="resume-agent-sessions"
      // data-action="checkpoint-agent"
      // data-action="handoff-agent"
      // data-action="failover-agent"
      const providers = state.data.agentProviders?.providers || [];
      const instances = state.data.agentInstances?.instances || [];
      const sessions = state.data.agentSessions?.sessions || [];
      const dispatches = state.data.agentDispatches?.dispatches || [];
      const results = state.data.agentDispatches?.results || [];
      const primary = instances.find((row) => row.primary || row.is_primary) || instances[0] || {};
      const providerId = primary.primary_provider_id || "codex";
      const provider = providers.find((row) => row.id === providerId) || {};
      const capabilities = provider.capabilities || {};
      const readinessBlocker = primary.current_driver_blocker || provider.unavailable_reason || "";
      const fallbackOrder = primary.approved_fallback_provider_ids || [];
      const activeEpoch = primary.active_epoch || null;
      const providerNativeUsage = state.data.agentUsage?.providers || [];
      const failoverExecutions = state.data.agentFailoverExecutions?.executions || [];
      const blockedFailoverExecution = failoverExecutions.find(
        (item) => ["reserved", "draining", "blocked_preimport", "recovering"].includes(item.recovery_state)
      );
      const blockerText = readinessBlocker ? JSON.stringify(readinessBlocker) : "";
      const cancelTitle = "Cancellation route is unavailable";
      const required = primary.required_capabilities || {};
      const selectedDiscoveryProvider = state.driverSelection["agent-provider-id"] || providerId;
      const selectedIncomingProvider = state.driverSelection["agent-incoming-provider-id"] || fallbackOrder[0] || "";
      const selectedSessionId = state.driverSelection["agent-session-id"] || sessions[0]?.id || "";
      const selectedSession = sessions.find((row) => row.id === selectedSessionId);
      const failoverBlocker = !primary.controlled_failover_policy_ref
        ? "Controlled failover policy is not configured"
        : primary.failover_policy_readiness !== "ready"
        ? JSON.stringify(primary.failover_policy_blocker || "Failover policy is not ready")
        : !fallbackOrder.includes(selectedIncomingProvider)
        ? "Incoming provider is not an approved fallback"
        : "";
      function driverAction(action, label, capability, destinationProvider, extraBlocker = "") {
        const gate = providerGate(providers, destinationProvider, required, capability);
        const reason = extraBlocker || gate.blocker;
        return `<button class="action-btn" data-action="${action}"${reason ? " disabled" : ""} title="${safe(reason || label)}"${reason ? ` aria-label="${safe(`${label}: ${reason}`)}"` : ""}>${safe(label)}</button>`;
      }
      document.getElementById("driver").innerHTML = `
        <div class="grid">
          ${stationIntro("Sisko", "Primary AI Driver", "One primary provider per Overseer instance with controlled recovery, manual handoff, and failover.", ["provider neutral", "epoch fenced", "approval gated"])}
          <div class="section-head"><h3>Driver Actions</h3><div class="actions">
            ${driverAction("discover-agent-sessions", "Discover Agent Sessions", "session_discovery", selectedDiscoveryProvider)}
            ${driverAction("resume-agent-sessions", "Resume Agent Sessions", "session_resume", selectedSession?.provider_id || "")}
            ${driverAction("checkpoint-agent", "Checkpoint", "checkpoints", selectedSession?.provider_id || providerId)}
            ${driverAction("handoff-agent", "Manual Handoff", "handoff_import", selectedIncomingProvider)}
            ${driverAction("failover-agent", "Controlled Failover", "handoff_import", selectedIncomingProvider, failoverBlocker)}
            <button class="action-btn" data-action="recover-agent-failover"${blockedFailoverExecution ? "" : " disabled"} title="${safe(blockedFailoverExecution?.blocker || "No recovery required")}">Recover Failover</button>
            <button class="action-btn" data-disabled-action="cancel-agent" disabled title="${safe(cancelTitle)}" aria-describedby="agent-cancel-blocker">Cancel</button>
          </div></div>
          <div id="agent-cancel-blocker" class="panel span-12 inactive">${safe(cancelTitle)}${blockerText ? `; ${safe(blockerText)}` : ""}</div>
          <div id="agent-failover-blockers" class="panel span-12 inactive">Evaluate controlled failover to view exact blockers.</div>
          ${blockedFailoverExecution ? `<div class="panel span-12 bad">Failover recovery required: ${safe(blockedFailoverExecution.id)} (${safe(blockedFailoverExecution.recovery_state)}): ${safe(blockedFailoverExecution.blocker)}. ${safe(blockedFailoverExecution.next_action)}</div>` : ""}
          <div class="panel span-12">
            <div class="toolbar"><h3>Operator Request</h3><span class="pill">${safe(providerId)}</span></div>
            <div class="form-grid">
              <div class="field span-3"><label for="agent-instance-id">Instance</label><input id="agent-instance-id" value="${safe(primary.id || "overseer.default")}"></div>
              <div class="field span-3"><label for="agent-provider-id">Discovery Provider</label><input id="agent-provider-id" value="${safe(selectedDiscoveryProvider)}"></div>
              <div class="field span-3"><label for="agent-incoming-provider-id">Incoming Provider</label><input id="agent-incoming-provider-id" value="${safe(selectedIncomingProvider)}"></div>
              <div class="field span-3"><label for="agent-session-id">Session</label><input id="agent-session-id" value="${safe(selectedSessionId)}"></div>
              <div class="field span-6"><label for="agent-approval-id">Approval ID</label><input id="agent-approval-id" autocomplete="off" placeholder="required for handoff or failover"></div>
              <div class="field span-6"><label for="agent-initiated-by">Initiated By</label><input id="agent-initiated-by" value="operator"></div>
            </div>
          </div>
          ${metric("Primary Provider", providerId, provider.readiness || primary.lifecycle_state || "unknown", "span-3", provider.available === false ? "bad" : "good")}
          ${metric("Lifecycle", activeEpoch ? "active" : "not started", "instance", "span-3", "")}
          ${metric("Driver Epoch", activeEpoch?.id || "none", "generation fence", "span-3", "")}
          ${metric("Sessions", sessions.length, "normalized", "span-3", "")}
          <div class="panel span-6">${kv("Checkpoint and Recovery", {
            checkpoint: primary.current_checkpoint_id,
            recovery: primary.transition_state,
            blocker: readinessBlocker
          })}</div>
          <div class="panel span-6">${kv("Fallback Order", {providers: fallbackOrder})}</div>
          <div class="panel span-12">${table("Provider Capabilities", providers.map((row) => ({
            provider_id: row.id,
            readiness: row.readiness,
            available: row.available,
            capabilities: row.capabilities,
            blocker: row.unavailable_reason
          })), ["provider_id", "readiness", "available", "capabilities", "blocker"])}</div>
          <div class="panel span-12">${table("Provider Native Usage", providerNativeUsage, ["provider_id", "usage_limit_source_id", "evidence_status", "value", "usage_unit"])}</div>
          <div class="panel span-6">${table("Agent Sessions", sessions, ["id", "provider_id", "instance_id", "state", "checkpoint_id"])}</div>
          <div class="panel span-6">${table("Agent Dispatches", dispatches, ["id", "instance_id", "session_id", "driver_epoch_id", "requested_at", "requested_by"])}</div>
          <div class="panel span-12">${table("Dispatch Results", results, ["request_id", "state", "completed_at", "error_category"])}</div>
          ${officerPanel("sisko", "Primary AI driver review", "Review provider readiness, epoch, checkpoint, and approval evidence before changing the primary driver.")}
        </div>`;
    }
    function renderAdmin() {
      const adapters = state.data.adapters || {};
      const auth = state.data.authorizations || {};
      const readiness = state.data.readiness || {};
      const activePolicy = state.data.activePolicy || {};
      const complianceEvidence = state.data.complianceEvidence || {};
      const policyHelper = state.data.policyHelper || {};
      const packageStatus = state.data.packageStatus || {};
      const firmwareStatus = state.data.firmwareStatus || {};
      const firmwarePreflight = state.data.firmwarePreflight || {};
      const softwareEvidence = state.data.softwareEvidence || {};
      const advisories = state.data.advisories || softwareEvidence.advisories || {};
      const maintenanceSchedules = state.data.maintenanceSchedules || {};
      const archivePlan = state.data.adminArchivePlan || {};
      const archives = state.data.adminArchives || {};
      const operations = state.data.operations || {};
      const profile = activePolicy.profile || {};
      document.getElementById("admin").innerHTML = `
        <div class="grid">
          ${stationIntro("O'Brien", "Maintenance Operations", "Protected changes, package work, and service restart gates.", ["admin plans", "policy profile", "maintenance"])}
          <div class="section-head"><h3>Admin Actions</h3><div class="actions"><button class="action-btn" data-action="discover-user-services">Discover Services</button><button class="action-btn" data-action="plan-package-updates">Plan Updates</button><button class="action-btn" data-action="plan-firmware-updates">Plan Firmware</button><button class="action-btn" data-action="run-package-maintenance-cycle">Run Package Cycle</button></div></div>
          ${metric("Adapters", adapters.enabled, "enabled", "span-3", adapters.disabled ? "warn" : "good", "admin")}
          ${metric("Authorizations", auth.pending_count, "pending", "span-3", auth.pending_count ? "warn" : "good", "admin")}
          ${metric("Ready", readiness.ready_for_overseer_execution, "executable now", "span-3", "", "admin")}
          ${metric("Failed", readiness.failed, "plans", "span-3", readiness.failed ? "bad" : "good", "audit")}
          <div class="panel span-12">
            <div class="toolbar"><h3>Plan Admin Change</h3><button class="action-btn" data-action="plan-admin-change">Plan Change</button></div>
            <div class="form-grid">
              <div class="field span-2"><label for="admin-plan-id">Plan ID</label><input id="admin-plan-id" value="admin.restart.local-service"></div>
              <div class="field span-2"><label for="admin-kind">Kind</label><select id="admin-kind">${adminKindOptions()}</select></div>
              <div class="field span-2"><label for="admin-target">Target</label><input id="admin-target" value="overseer-api.service"></div>
              <div class="field span-2"><label for="admin-current-state">Current State</label><input id="admin-current-state" value="active"></div>
              <div class="field span-2"><label for="admin-package">Package</label><input id="admin-package"></div>
              <div class="field span-2"><label for="admin-port">Port</label><input id="admin-port" type="number" min="1" max="65535"></div>
              <div class="field span-3"><label for="admin-compose-project-directory">Compose Dir</label><input id="admin-compose-project-directory" placeholder="/home/god/penpot"></div>
              <div class="field span-3"><label for="admin-compose-env">Compose Env</label><input id="admin-compose-env" placeholder="PENPOT_VERSION=2.17.0"></div>
              <div class="field span-3"><label for="admin-compose-rollback-env">Rollback Env</label><input id="admin-compose-rollback-env" placeholder="PENPOT_VERSION=2.16"></div>
              <div class="field span-6"><label for="admin-compose-extra-files">Extra Compose Files</label><input id="admin-compose-extra-files" placeholder="/home/god/penpot/local-secrets/admin-overrides/override.yaml"></div>
              <div class="field span-3"><label for="admin-health-url">Health URL</label><input id="admin-health-url" placeholder="http://127.0.0.1:9001/"></div>
              <div class="field span-6"><label for="admin-compose-scan-images">Scan Images</label><input id="admin-compose-scan-images" placeholder="penpotapp/frontend:2.17.0, postgres:15"></div>
              <div class="field span-6"><label for="admin-compose-residual-scan-findings">Residual Scan Findings</label><input id="admin-compose-residual-scan-findings" placeholder="penpotapp/exporter:2.17 retains critical findings after risk reduction"></div>
              <div class="field span-3"><label for="admin-backup-label">Backup Label</label><input id="admin-backup-label" placeholder="penpot-update"></div>
              <div class="field span-4"><label for="admin-mount-path">Mount Path</label><input id="admin-mount-path" placeholder="/home/god/Documents/Codex Workspace/Overseer/local-secrets/mounts/mediastore"></div>
              <div class="field span-5"><label for="admin-credential-file">Credential File</label><input id="admin-credential-file" placeholder="/home/god/Documents/Codex Workspace/Overseer/local-secrets/backup-providers/mediastore/credentials.conf"></div>
              <div class="field span-3"><label for="admin-filesystem-type">Filesystem</label><input id="admin-filesystem-type" value="cifs"></div>
              <div class="field span-3"><label for="admin-use-firewalld">Firewall Backend</label><select id="admin-use-firewalld"><option value="false">ufw</option><option value="true">firewalld</option></select></div>
              <div class="field span-6"><label for="admin-reason">Reason</label><input id="admin-reason" value="operator requested maintenance"></div>
            </div>
          </div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Maintenance Schedule</h3><button class="action-btn" data-action="record-maintenance-schedule">Record Schedule</button></div>
            <div class="form-grid">
              <div class="field span-2"><label for="maintenance-schedule-id">Schedule ID</label><input id="maintenance-schedule-id" value="schedule.weekly.updates"></div>
              <div class="field span-3"><label for="maintenance-schedule-target">Target</label><input id="maintenance-schedule-target" value="local packages"></div>
              <div class="field span-2"><label for="maintenance-schedule-recurrence">Recurrence</label><input id="maintenance-schedule-recurrence" value="weekly"></div>
              <div class="field span-3"><label for="maintenance-schedule-window">Window</label><input id="maintenance-schedule-window" value="Sunday 02:00-04:00"></div>
              <div class="field span-2"><label for="maintenance-schedule-timezone">Timezone</label><input id="maintenance-schedule-timezone" value="UTC"></div>
              <div class="field span-3"><label for="maintenance-schedule-owner">Owner</label><select id="maintenance-schedule-owner">${ownerOptions()}</select></div>
              <div class="field span-3"><label for="maintenance-schedule-risk">Risk</label><select id="maintenance-schedule-risk">${riskOptions()}</select></div>
              <div class="field span-3"><label for="maintenance-schedule-status">Status</label><select id="maintenance-schedule-status">${maintenanceScheduleStatusOptions()}</select></div>
              <div class="field span-3"><label for="maintenance-schedule-blackout">Blackout</label><input id="maintenance-schedule-blackout" value="none"></div>
              <div class="field span-4"><label for="maintenance-schedule-validation">Validation</label><input id="maintenance-schedule-validation" value="run health probes and service evidence"></div>
              <div class="field span-4"><label for="maintenance-schedule-rollback">Rollback</label><input id="maintenance-schedule-rollback" value="use related admin plan rollback steps"></div>
              <div class="field span-4"><label for="maintenance-schedule-notes">Notes</label><input id="maintenance-schedule-notes"></div>
              <div class="field span-12"><label for="maintenance-schedule-metadata">Metadata</label><textarea id="maintenance-schedule-metadata">{}</textarea></div>
            </div>
          </div>
          <div class="panel span-4">
            <div class="toolbar"><h3>Approve Plan</h3><button class="action-btn" data-action="approve-admin-change">Approve</button></div>
            <div class="form-grid">
              <div class="field span-6"><label for="admin-approval-plan-id">Plan ID</label><input id="admin-approval-plan-id"></div>
              <div class="field span-6"><label for="admin-approved-by">Approved By</label><input id="admin-approved-by" value="sisko"></div>
            </div>
          </div>
          <div class="panel span-4">
            <div class="toolbar"><h3>Execute Plan</h3><button class="action-btn" data-action="execute-admin-change">Execute</button></div>
            <div class="form-grid">
              <div class="field span-6"><label for="admin-execute-plan-id">Plan ID</label><input id="admin-execute-plan-id"></div>
            </div>
          </div>
          <div class="panel span-4">
            <div class="toolbar"><h3>Cancel Plan</h3><button class="action-btn" data-action="cancel-admin-change">Cancel</button></div>
            <div class="form-grid">
              <div class="field span-6"><label for="admin-cancel-plan-id">Plan ID</label><input id="admin-cancel-plan-id"></div>
              <div class="field span-3"><label for="admin-canceled-by">By</label><input id="admin-canceled-by" value="sisko"></div>
              <div class="field span-3"><label for="admin-cancel-reason">Reason</label><input id="admin-cancel-reason"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Adapter Enablement</h3><div class="actions"><button class="action-btn" data-action="request-admin-adapter-enablement">Request</button><button class="action-btn" data-action="approve-admin-adapter-enablement">Approve</button></div></div>
            <div class="form-grid">
              <div class="field span-4"><label for="admin-adapter-kind">Kind</label><select id="admin-adapter-kind">${adminKindOptions()}</select></div>
              <div class="field span-4"><label for="admin-adapter-requested-by">Requested By</label><input id="admin-adapter-requested-by" value="sisko"></div>
              <div class="field span-4"><label for="admin-adapter-approval-id">Approval ID</label><input id="admin-adapter-approval-id"></div>
              <div class="field span-4"><label for="admin-adapter-approved-by">Approved By</label><input id="admin-adapter-approved-by" value="sisko"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Archive History</h3><div class="actions"><button class="action-btn" data-action="request-admin-archive">Request</button><button class="action-btn" data-action="approve-admin-archive">Approve</button><button class="action-btn" data-action="archive-admin-history">Archive</button></div></div>
            <div class="form-grid">
              <div class="field span-4"><label for="admin-archive-plan-id">Plan ID</label><input id="admin-archive-plan-id"></div>
              <div class="field span-4"><label for="admin-archive-requested-by">Requested By</label><input id="admin-archive-requested-by" value="sisko"></div>
              <div class="field span-4"><label for="admin-archive-approval-id">Approval ID</label><input id="admin-archive-approval-id"></div>
              <div class="field span-4"><label for="admin-archive-approved-by">Approved By</label><input id="admin-archive-approved-by" value="sisko"></div>
              <div class="field span-4"><label for="admin-archive-execute-approval-id">Execute Approval</label><input id="admin-archive-execute-approval-id"></div>
              <div class="field span-4"><label for="admin-archive-execute-plan-id">Execute Plan</label><input id="admin-archive-execute-plan-id"></div>
              <div class="field span-4"><label for="admin-archived-by">Archived By</label><input id="admin-archived-by" value="sisko"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Restore History</h3><div class="actions"><button class="action-btn" data-action="request-admin-restore">Request</button><button class="action-btn" data-action="approve-admin-restore">Approve</button><button class="action-btn" data-action="unarchive-admin-history">Restore</button></div></div>
            <div class="form-grid">
              <div class="field span-4"><label for="admin-restore-plan-id">Plan ID</label><input id="admin-restore-plan-id"></div>
              <div class="field span-4"><label for="admin-restore-requested-by">Requested By</label><input id="admin-restore-requested-by" value="sisko"></div>
              <div class="field span-4"><label for="admin-restore-approval-id">Approval ID</label><input id="admin-restore-approval-id"></div>
              <div class="field span-4"><label for="admin-restore-approved-by">Approved By</label><input id="admin-restore-approved-by" value="sisko"></div>
              <div class="field span-4"><label for="admin-unarchive-plan-id">Restore Plan</label><input id="admin-unarchive-plan-id"></div>
              <div class="field span-4"><label for="admin-unarchive-approval-id">Restore Approval</label><input id="admin-unarchive-approval-id"></div>
              <div class="field span-4"><label for="admin-unarchived-by">Restored By</label><input id="admin-unarchived-by" value="sisko"></div>
            </div>
          </div>
          <div class="panel span-4">${kv("Package Status", {
            status: packageStatus.status,
            upgradable: packageStatus.upgradable,
            captured_at: packageStatus.captured_at,
            stderr: packageStatus.stderr
          })}</div>
          <div class="panel span-8">${table("Upgradable Packages", packageStatus.items || [], ["name", "installed_version", "candidate_version", "repository"])}</div>
          <div class="panel span-4">${kv("Firmware Status", {
            status: firmwareStatus.status,
            updates: firmwareStatus.updates,
            high_urgency: firmwareStatus.high_urgency,
            blocked_updates: firmwareStatus.blocked_updates,
            reboot_required: firmwareStatus.reboot_required,
            next_step: firmwareStatus.next_step
          })}</div>
          <div class="panel span-8">${table("Firmware Updates", firmwareStatus.items || [], ["device", "title", "current_version", "new_version", "urgency", "status", "blocker_type", "reboot_required"])}</div>
          <div class="panel span-12">${table("Firmware Blocker Guidance", firmwareBlockerRows(firmwareStatus.items || []), ["device", "blocker_type", "blocker_resolution", "safe_preflight"])}</div>
          <div class="panel span-4">${kv("Firmware Preflight", {
            status: firmwarePreflight.status,
            efivar_accessible: firmwarePreflight.efivar_accessible,
            efivar_count: firmwarePreflight.efivar_count,
            stale_dump_candidate_count: firmwarePreflight.stale_dump_candidate_count,
            next_step: firmwarePreflight.next_step
          })}</div>
          <div class="panel span-8">${table("Largest EFI Variables", firmwarePreflight.largest || [], ["name", "size_bytes"])}</div>
          <div class="panel span-12">${table("Stale EFI Dump Candidates", firmwarePreflight.stale_dump_candidates || [], ["name", "size_bytes"])}</div>
          <div class="panel span-12">${kv("Active Policy Profile", {
            name: profile.name,
            source: activePolicy.source,
            customized: activePolicy.customized,
            warnings_block_execution: profile.block_warnings_until_accepted,
            path: activePolicy.path,
            next_step: activePolicy.next_step
          })}</div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Policy Customization Helper</h3><button class="action-btn" data-action="build-policy-profile">Build Profile</button></div>
            <div class="form-grid">
              <div class="field span-3"><label for="policy-profile-name">Name</label><input id="policy-profile-name" value="custom"></div>
              <div class="field span-9"><label for="policy-profile-description">Description</label><input id="policy-profile-description" value="Customized Overseer policy profile."></div>
              ${policyQuestionControls(policyHelper.questions || [])}
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Policy Warning Acceptance</h3><div class="actions"><button class="action-btn" data-action="request-policy-warning">Request</button><button class="action-btn" data-action="approve-policy-warning">Approve</button></div></div>
            <div class="form-grid">
              <div class="field span-4"><label for="policy-warning-plan-id">Plan ID</label><input id="policy-warning-plan-id"></div>
              <div class="field span-4"><label for="policy-warning-check-id">Check ID</label><input id="policy-warning-check-id" value="admin.rollback"></div>
              <div class="field span-4"><label for="policy-warning-requested-by">Requested By</label><input id="policy-warning-requested-by" value="sisko"></div>
              <div class="field span-4"><label for="policy-warning-approval-id">Approval ID</label><input id="policy-warning-approval-id"></div>
              <div class="field span-4"><label for="policy-warning-approved-by">Approved By</label><input id="policy-warning-approved-by" value="human"></div>
            </div>
          </div>
          ${authorizationDecisionBoard(auth, readiness)}
          <div class="panel span-6">${table("Adapter Capabilities", adapters.items || [], ["kind", "status", "adapter_name"])}</div>
          <div class="panel span-6">${table("Execution Readiness", readiness.items || [], ["id", "kind", "readiness_state", "next_step"], {fills: {id: (row) => adminPlanFill(row.id)}, fillView: "admin"})}</div>
          <div class="panel span-6">${table("Archive Candidates", archivePlan.items || [], ["plan_id", "disposition", "next_step"])}</div>
          <div class="panel span-6">${table("Archived Plans", archives.items || [], ["plan_id", "disposition", "archived_by", "archived_at"])}</div>
          <div class="panel span-6">${table("Change Calendar", operations.change_calendar || [], ["id", "kind", "target", "status", "window", "rollback"], {fills: {id: (row) => adminPlanFill(row.id)}, fillView: "admin"})}</div>
          <div class="panel span-6">${table("Maintenance Schedules", maintenanceSchedules.items || [], ["id", "target", "recurrence", "window", "timezone", "status"], {fills: {id: (row) => maintenanceScheduleFill(row)}, fillView: "admin"})}</div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Advisory Refresh</h3><button class="action-btn" data-action="refresh-advisories">Refresh Advisories</button></div>
            <div class="form-grid">
              <div class="field span-6"><label for="advisory-packages">Packages</label><textarea id="advisory-packages">${safe((advisories.requested_packages || []).join(", ") || "openssl, openssh, sudo, curl, apt, dpkg, systemd, python3")}</textarea></div>
              <div class="field span-2"><label for="advisory-source">Source</label><select id="advisory-source">${advisorySourceOptions()}</select></div>
              <div class="field span-2"><label for="advisory-max-results">Max Results</label><input id="advisory-max-results" type="number" min="1" max="20" value="5"></div>
              <div class="field span-2"><label for="advisory-requested-by">Requested By</label><input id="advisory-requested-by" value="obrien"></div>
              <div class="field span-3 inline-check"><label for="advisory-dry-run"><input id="advisory-dry-run" type="checkbox"> Dry Run</label></div>
            </div>
          </div>
          <div class="panel span-6">${kv("Advisory Feed Status", {
            status: advisories.status,
            cached_records: advisories.cached_records,
            finding_count: advisories.finding_count,
            oldest_cache_age_seconds: advisories.oldest_cache_age_seconds,
            next_step: advisories.next_step
          })}</div>
          <div class="panel span-6">${table("Advisory Sources", advisories.sources || [], ["source", "name", "status", "url"], {links: {url: (row) => row.url}})}</div>
          <div class="panel span-6">${table("Advisory Package Summary", advisories.package_summary || [], ["package", "findings", "critical", "high", "medium", "low", "next_step"])}</div>
          <div class="panel span-6">${kv("Advisory Severity", advisories.by_severity || {})}</div>
          <div class="panel span-12">${table("Advisory Findings", advisories.findings || [], ["package", "source", "cve_id", "severity", "published", "last_modified", "summary", "url"], {links: {url: (row) => row.url}})}</div>
          <div class="panel span-6">${table("Patch And Software Inventory", [operations.software_inventory || {}], ["dpkg_packages", "held_packages", "pip_packages", "flatpak_apps", "next_step"])}</div>
          <div class="panel span-6">${table("Package Manager Evidence", softwareEvidence.package_managers || [], ["manager", "available"])}</div>
          <div class="panel span-6">${table("Package Provenance", softwareEvidence.provenance || [], ["source", "present", "status"])}</div>
          <div class="panel span-6">${table("Release Note References", softwareEvidence.release_notes || [], ["path", "present", "status"])}</div>
          <div class="panel span-12">${table("Patch Readiness", softwareEvidence.patch_readiness || [], ["check", "status", "next_step"])}</div>
          <div class="panel span-12">${table("Compliance And Drift", operations.compliance || [], ["area", "status", "evidence", "next_step"])}</div>
          <div class="panel span-6">${table("Policy Exceptions", complianceEvidence.policy_exceptions || [], ["approval_id", "subject_id", "status", "level", "owner_domain"], {fills: {approval_id: (row) => ({ "admin-approval-plan-id": row.subject_id || "" })}, fillView: "admin"})}</div>
          <div class="panel span-6">${table("Desired State Baselines", complianceEvidence.desired_state || [], ["area", "path", "present", "status"])}</div>
          <div class="panel span-6">${table("Desired State Drift", complianceEvidence.desired_state_drift || [], ["area", "expected", "status", "next_step"])}</div>
          <div class="panel span-6">${table("Local Secret Guards", complianceEvidence.local_secret_guards || [], ["pattern", "present", "status"])}</div>
          <div class="panel span-6">${table("Compliance Evidence Matrix", complianceEvidence.evidence_matrix || [], ["area", "records", "status"])}</div>
          ${officerPanel("sisko", "Administrative decision", "Plan, approve, or coordinate a protected administrative change.")}
          ${officerPanel("obrien", "Maintenance deployment", "Schedule updates, patches, or service maintenance.")}
        </div>`;
    }
    function renderAssets() {
      const physical = state.data.physical || {};
      const virtual = state.data.virtual || {};
      const operations = state.data.operations || {};
      const storageEvidence = state.data.storageEvidence || {};
      const backupOperations = state.data.backupOperations || {};
      document.getElementById("assets").innerHTML = `
        <div class="grid">
          ${stationIntro("Kira / Dax", "Asset Control", "Physical inventory and virtual checkout surfaces.", ["USB and storage", "listeners", "virtual assets"])}
          <div class="section-head"><h3>Asset Actions</h3><div class="actions"><button class="action-btn" data-action="discover-physical">Discover Devices</button><button class="action-btn" data-action="discover-storage">Discover Storage</button><button class="action-btn" data-action="discover-listeners">Discover Listeners</button></div></div>
          ${metric("Physical", physical.assets, "assets", "span-3", "", "assets")}
          ${metric("Checkout Ready", physical.ready_for_checkout, "physical", "span-3", "", "claims")}
          ${metric("Virtual", virtual.assets, "assets", "span-3", "", "assets")}
          ${metric("Active Claims", virtual.active_claims, "virtual", "span-3", virtual.active_claims ? "warn" : "good", "claims")}
          <div class="panel span-12">
            <div class="toolbar"><h3>Resource Registry</h3><button class="action-btn" data-action="register-resource">Record Resource</button></div>
            <div class="form-grid">
              <div class="field span-2"><label for="resource-id">Resource ID</label><input id="resource-id" value="svc.local.service"></div>
              <div class="field span-2"><label for="resource-name">Name</label><input id="resource-name" value="Local Service"></div>
              <div class="field span-2"><label for="resource-type">Type</label><select id="resource-type">${resourceTypeOptions()}</select></div>
              <div class="field span-2"><label for="resource-owner">Owner</label><select id="resource-owner">${ownerOptions()}</select></div>
              <div class="field span-2"><label for="resource-risk">Risk</label><select id="resource-risk">${riskOptions()}</select></div>
              <div class="field span-6"><label for="resource-identifiers">Identifiers</label><input id="resource-identifiers" value='{"kind":"service"}'></div>
            </div>
          </div>
          <div class="panel span-6">${table("Physical Assets", physical.items || [], ["id", "kind", "stable_id", "checkout_ready"], {fills: {id: (row) => resourceClaimFill(row.id, "kira")}, fillView: "claims"})}</div>
          <div class="panel span-6">${table("Virtual Assets", virtual.items || [], ["id", "name", "state", "current_claim_id"], {fills: {id: (row) => resourceClaimFill(row.id, "dax"), current_claim_id: (row) => claimFill(row.current_claim_id)}, fillView: "claims"})}</div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Backup Job Registry</h3><button class="action-btn" data-action="record-backup-job">Record Job</button></div>
            <div class="form-grid">
              <div class="field span-2"><label for="backup-job-id">Job ID</label><input id="backup-job-id" value="backup.local.state"></div>
              <div class="field span-3"><label for="backup-target">Target</label><input id="backup-target" value="state/"></div>
              <div class="field span-2"><label for="backup-schedule">Schedule</label><input id="backup-schedule" value="manual"></div>
              <div class="field span-2"><label for="backup-retention">Retention</label><input id="backup-retention" value="operator-defined"></div>
              <div class="field span-1"><label for="backup-risk">Risk</label><select id="backup-risk">${riskOptions()}</select></div>
              <div class="field span-1"><label for="backup-status">Status</label><input id="backup-status" value="staged"></div>
              <div class="field span-1"><label for="backup-requested-by">By</label><input id="backup-requested-by" value="kira"></div>
              <div class="field span-12"><label for="backup-notes">Notes</label><input id="backup-notes"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Restore Test Record</h3><button class="action-btn" data-action="record-restore-test">Record Test</button></div>
            <div class="form-grid">
              <div class="field span-4"><label for="restore-test-id">Test ID</label><input id="restore-test-id" value="restore.local.state"></div>
              <div class="field span-4"><label for="restore-job-id">Job ID</label><input id="restore-job-id" value="backup.local.state"></div>
              <div class="field span-4"><label for="restore-point">Restore Point</label><input id="restore-point" value="backups/restore-test.md"></div>
              <div class="field span-4"><label for="restore-status">Status</label><input id="restore-status" value="planned"></div>
              <div class="field span-4"><label for="restore-validated-by">Validated By</label><input id="restore-validated-by" value="kira"></div>
              <div class="field span-12"><label for="restore-notes">Notes</label><input id="restore-notes"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Backup Execution Request</h3><div class="actions"><button class="action-btn" data-action="stage-backup-execution-request">Stage</button><button class="action-btn" data-action="approve-backup-execution-request">Approve</button><button class="action-btn" data-action="execute-backup-execution-request">Execute</button></div></div>
            <div class="form-grid">
              <div class="field span-6"><label for="backup-exec-request-id">Request ID</label><input id="backup-exec-request-id"></div>
              <div class="field span-6"><label for="backup-exec-source-path">Source Path</label><input id="backup-exec-source-path" value="state"></div>
              <div class="field span-4"><label for="backup-exec-backup-name">Backup Name</label><input id="backup-exec-backup-name" value="local-state"></div>
              <div class="field span-4"><label for="backup-exec-requested-by">Requested By</label><input id="backup-exec-requested-by" value="kira"></div>
              <div class="field span-4"><label for="backup-exec-approved-by">Approved By</label><input id="backup-exec-approved-by" value="kira"></div>
              <div class="field span-4"><label for="backup-exec-executed-by">Executed By</label><input id="backup-exec-executed-by" value="kira"></div>
              <div class="field span-12"><label for="backup-exec-reason">Reason</label><input id="backup-exec-reason" value="stage approved local backup execution"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Restore Execution Request</h3><div class="actions"><button class="action-btn" data-action="stage-restore-execution-request">Stage</button><button class="action-btn" data-action="approve-restore-execution-request">Approve</button><button class="action-btn" data-action="execute-restore-execution-request">Execute</button></div></div>
            <div class="form-grid">
              <div class="field span-6"><label for="restore-exec-request-id">Request ID</label><input id="restore-exec-request-id"></div>
              <div class="field span-6"><label for="restore-exec-backup-path">Backup Path</label><input id="restore-exec-backup-path" value="backups/overseer-managed/local-state"></div>
              <div class="field span-6"><label for="restore-exec-restore-target">Restore Target</label><input id="restore-exec-restore-target" value="artifacts/restore-test/local-state"></div>
              <div class="field span-3"><label for="restore-exec-requested-by">Requested By</label><input id="restore-exec-requested-by" value="kira"></div>
              <div class="field span-3"><label for="restore-exec-approved-by">Approved By</label><input id="restore-exec-approved-by" value="kira"></div>
              <div class="field span-3"><label for="restore-exec-executed-by">Executed By</label><input id="restore-exec-executed-by" value="kira"></div>
              <div class="field span-12"><label for="restore-exec-reason">Reason</label><input id="restore-exec-reason" value="stage approved local restore execution"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Backup Cleanup Request</h3><div class="actions"><button class="action-btn" data-action="stage-backup-cleanup-request">Stage</button><button class="action-btn" data-action="approve-backup-cleanup-request">Approve</button><button class="action-btn" data-action="execute-backup-cleanup-request">Execute</button></div></div>
            <div class="form-grid">
              <div class="field span-6"><label for="backup-cleanup-request-id">Request ID</label><input id="backup-cleanup-request-id"></div>
              <div class="field span-6"><label for="backup-cleanup-path">Path</label><input id="backup-cleanup-path" value="artifacts"></div>
              <div class="field span-3"><label for="backup-cleanup-requested-by">Requested By</label><input id="backup-cleanup-requested-by" value="kira"></div>
              <div class="field span-3"><label for="backup-cleanup-approved-by">Approved By</label><input id="backup-cleanup-approved-by" value="kira"></div>
              <div class="field span-3"><label for="backup-cleanup-executed-by">Executed By</label><input id="backup-cleanup-executed-by" value="kira"></div>
              <div class="field span-12"><label for="backup-cleanup-reason">Reason</label><input id="backup-cleanup-reason" value="review generated storage cleanup candidate"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Storage Growth Snapshot</h3><button class="action-btn" data-action="capture-storage-growth-snapshot">Capture Growth</button></div>
            <div class="form-grid">
              <div class="field span-3"><label for="storage-growth-snapshot-id">Snapshot ID</label><input id="storage-growth-snapshot-id" placeholder="optional"></div>
              <div class="field span-2"><label for="storage-growth-requested-by">Requested By</label><input id="storage-growth-requested-by" value="kira"></div>
              <div class="field span-1"><label for="storage-growth-retention">Retention</label><input id="storage-growth-retention" type="number" min="1" value="250"></div>
              <div class="field span-6"><label for="storage-growth-notes">Notes</label><input id="storage-growth-notes" value="capture filesystem growth evidence"></div>
            </div>
          </div>
          <div class="panel span-6">${table("Storage And Backup", [operations.storage_backup || {}], ["mount_rows", "backup_markers", "restore_tests", "next_step"])}</div>
          <div class="panel span-6">${table("Mount Health", storageEvidence.mounts || [], ["source", "type", "available", "use_percent", "mount", "status"])}</div>
          <div class="panel span-6">${table("SMART Health", storageEvidence.smart_health || [], ["device", "available", "status", "exit_code"])}</div>
          <div class="panel span-6">${table("Backup Markers", storageEvidence.backup_markers || [], ["path", "kind", "status"])}</div>
          <div class="panel span-12">${table("Backup Jobs", backupOperations.jobs || storageEvidence.backup_jobs || [], ["id", "target", "schedule", "retention", "status", "next_step"], {fills: {id: (row) => backupJobFill(row)}, fillView: "assets"})}</div>
          <div class="panel span-12">${table("Backup Provider Targets", backupOperations.provider_targets || storageEvidence.backup_provider_targets || [], ["id", "name", "target", "provider_class", "protocols", "tooling", "role", "status", "credential_status", "smb_helper_status", "name_resolution_status", "mount_path", "next_step"])}</div>
          <div class="panel span-12">${table("Backup Provider Readiness", backupOperations.provider_readiness || storageEvidence.backup_provider_readiness || [], ["id", "provider_class", "target", "role", "status", "connection_status", "credential_status", "smb_helper_status", "name_resolution_status", "mount_path", "can_stage", "can_execute", "blockers", "next_step"])}</div>
          <div class="panel span-12">${table("Backup Provider Local Profiles", backupOperations.provider_local_profiles || storageEvidence.backup_provider_local_profiles || [], ["id", "name", "share", "credential_status", "credential_mode", "username_status", "smb_helper_status", "name_resolution_status", "resolved_addresses", "mount_path", "mounted", "connection_status", "next_step"])}</div>
          <div class="panel span-12">${table("Backup Provider Classes", backupOperations.provider_classes || storageEvidence.backup_provider_classes || [], ["provider_class", "standard_options", "current_target", "status", "test_status"])}</div>
          <div class="panel span-12">${table("Restore Tests", backupOperations.restore_tests || storageEvidence.restore_tests || [], ["id", "job_id", "restore_point", "status", "validated_by", "next_step"], {fills: {id: (row) => restoreTestFill(row), job_id: (row) => backupJobFill({id: row.job_id})}, fillView: "assets"})}</div>
          <div class="panel span-12">${table("Backup Execution Requests", backupOperations.backup_requests || storageEvidence.backup_requests || [], ["id", "source_path", "backup_path", "status", "approval_required", "next_step"], {fills: {id: (row) => backupExecutionFill(row), backup_path: (row) => restoreExecutionFill({backup_path: row.backup_path})}, fillView: "assets"})}</div>
          <div class="panel span-12">${table("Restore Execution Requests", backupOperations.restore_requests || storageEvidence.restore_requests || [], ["id", "backup_path", "restore_target", "restored_path", "status", "next_step"], {fills: {id: (row) => restoreExecutionFill(row), backup_path: (row) => restoreExecutionFill(row)}, fillView: "assets"})}</div>
          <div class="panel span-12">${table("Backup Cleanup Requests", backupOperations.cleanup_requests || storageEvidence.cleanup_requests || [], ["id", "path", "status", "approval_required", "next_step"], {fills: {path: (row) => backupCleanupFill(row)}, fillView: "assets"})}</div>
          <div class="panel span-6">${table("Storage Cleanup Candidates", storageEvidence.cleanup_candidates || [], ["path", "kind", "status"])}</div>
          <div class="panel span-6">${kv("Capacity Summary", storageEvidence.capacity_summary || {})}</div>
          <div class="panel span-12">${table("Storage Risk Alerts", storageEvidence.risk_alerts || [], ["path", "kind", "risk_level", "status", "size_bytes", "next_step"])}</div>
          <div class="panel span-12">${table("Storage Encryption Trust", storageEvidence.encryption_trust || [], ["device", "model", "removable", "read_only", "encrypted", "trust_status", "risk_level", "approval_required", "next_step"])}</div>
          <div class="panel span-12">${table("Removable Media Review", storageEvidence.removable_media_review || [], ["device", "model", "trust_status", "risk_level", "approval_required", "next_step"])}</div>
          <div class="panel span-12">${table("Filesystem Growth Trends", storageEvidence.growth_trends || [], ["mount", "samples", "latest_use_percent", "daily_growth_bytes", "status", "next_step"])}</div>
          <div class="panel span-12">${table("Storage Growth Samples", storageEvidence.growth_samples || [], ["id", "captured_at", "requested_by", "notes", "next_step"], {limit: 20})}</div>
          <div class="panel span-6">${table("Physical Lifecycle", operations.physical_lifecycle || [], ["stable_id", "kind", "checkout_ready", "power_risk", "storage_risk", "next_step"], {fills: {stable_id: (row) => resourceClaimFill(row.stable_id, "kira")}, fillView: "claims"})}</div>
          ${officerPanel("kira", "Physical asset issue", "Handle a USB, serial, power, storage, or connected-device issue.")}
          ${officerPanel("dax", "Virtual asset checkout", "Handle an emulator, VM, gateway, proxy, listener, or virtual checkout issue.")}
        </div>`;
    }
    function renderClaims() {
      const claims = state.data.claims || {};
      const cleanup = state.data.claimCleanup || {};
      const operations = state.data.operations || {};
      const virtualEvidence = state.data.virtualEvidence || {};
      const virtualOperations = state.data.virtualOperations || {};
      const imageScans = state.data.imageScans || {};
      document.getElementById("claims").innerHTML = `
        <div class="grid">
          ${stationIntro("Dax", "Deconfliction Matrix", "Claims, leases, locks, and cleanup handoffs.", ["active claims", "approvals", "cleanup"])}
          ${metric("Active", claims.active_like, "claims", "span-3", "", "claims")}
          ${metric("Queued", claims.queued, "claims", "span-3", claims.queued ? "warn" : "good", "claims")}
          ${metric("Review", claims.operator_review_required, "required", "span-3", claims.operator_review_required ? "bad" : "good", "claims")}
          ${metric("Cleanup", cleanup.cleanup_candidates, "candidates", "span-3", cleanup.cleanup_candidates ? "warn" : "good", "claims")}
          <div class="panel span-12">
            <div class="toolbar"><h3>Request Claim</h3><button class="action-btn" data-action="request-claim">Request Claim</button></div>
            <div class="form-grid">
              <div class="field span-2"><label for="claim-id">Claim ID</label><input id="claim-id" value="claim.local.resource"></div>
              <div class="field span-2"><label for="claim-resource-id">Resource ID</label><input id="claim-resource-id" value="svc.systemd-user.overseer-api"></div>
              <div class="field span-2"><label for="claim-type">Type</label><select id="claim-type">${claimTypeOptions()}</select></div>
              <div class="field span-2"><label for="claim-owner-thread">Thread</label><input id="claim-owner-thread" value="operator-console"></div>
              <div class="field span-2"><label for="claim-owner-role">Owner</label><select id="claim-owner-role">${ownerOptions()}</select></div>
              <div class="field span-2"><label for="claim-risk">Risk</label><select id="claim-risk">${riskOptions()}</select></div>
              <div class="field span-2"><label for="claim-port">Port</label><input id="claim-port" type="number" min="1" max="65535"></div>
              <div class="field span-2"><label for="claim-expires-at">Expires At</label><input id="claim-expires-at"></div>
              <div class="field span-2"><label for="claim-release-condition">Release Condition</label><input id="claim-release-condition"></div>
              <div class="field span-3"><label for="claim-intent">Intent</label><input id="claim-intent" value="operate local resource"></div>
              <div class="field span-3"><label for="claim-action">Action</label><input id="claim-action" value="observe health"></div>
            </div>
          </div>
          <div class="panel span-4">
            <div class="toolbar"><h3>Approve</h3><button class="action-btn" data-action="approve-claim">Approve</button></div>
            <div class="form-grid">
              <div class="field span-6"><label for="claim-approval-id">Approval ID</label><input id="claim-approval-id"></div>
              <div class="field span-6"><label for="claim-decided-by">Decided By</label><input id="claim-decided-by" value="sisko"></div>
            </div>
          </div>
          <div class="panel span-4">
            <div class="toolbar"><h3>Activate</h3><button class="action-btn" data-action="activate-claim">Activate</button></div>
            <div class="form-grid">
              <div class="field span-6"><label for="claim-activate-id">Claim ID</label><input id="claim-activate-id"></div>
              <div class="field span-6"><label for="claim-activate-approval-id">Approval ID</label><input id="claim-activate-approval-id"></div>
            </div>
          </div>
          <div class="panel span-4">
            <div class="toolbar"><h3>Release</h3><button class="action-btn" data-action="release-claim">Release</button></div>
            <div class="form-grid">
              <div class="field span-6"><label for="claim-release-id">Claim ID</label><input id="claim-release-id"></div>
              <div class="field span-3"><label for="claim-released-by">By</label><input id="claim-released-by" value="sisko"></div>
              <div class="field span-3"><label for="claim-release-reason">Reason</label><input id="claim-release-reason"></div>
            </div>
          </div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Cleanup</h3><div class="actions"><button class="action-btn" data-action="request-claim-cleanup">Request</button><button class="action-btn" data-action="approve-claim-cleanup">Approve</button><button class="action-btn" data-action="execute-claim-cleanup">Execute</button></div></div>
            <div class="form-grid">
              <div class="field span-2"><label for="cleanup-claim-id">Claim ID</label><input id="cleanup-claim-id"></div>
              <div class="field span-2"><label for="cleanup-requested-by">Requested By</label><input id="cleanup-requested-by" value="sisko"></div>
              <div class="field span-2"><label for="cleanup-approval-id">Approval ID</label><input id="cleanup-approval-id"></div>
              <div class="field span-2"><label for="cleanup-approved-by">Approved By</label><input id="cleanup-approved-by" value="sisko"></div>
              <div class="field span-2"><label for="cleanup-execute-approval-id">Execute Approval</label><input id="cleanup-execute-approval-id"></div>
              <div class="field span-2"><label for="cleanup-executed-by">Executed By</label><input id="cleanup-executed-by" value="sisko"></div>
            </div>
          </div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Virtual Runtime Record</h3><button class="action-btn" data-action="record-virtual-runtime">Record Runtime</button></div>
            <div class="form-grid">
              <div class="field span-3"><label for="virtual-resource-id">Resource ID</label><input id="virtual-resource-id" value="vm.local.resource"></div>
              <div class="field span-2"><label for="virtual-kind">Kind</label><input id="virtual-kind" value="vm"></div>
              <div class="field span-2"><label for="virtual-state">State</label><input id="virtual-state" value="observed"></div>
              <div class="field span-2"><label for="virtual-adapter">Adapter</label><input id="virtual-adapter" value="manual"></div>
              <div class="field span-3"><label for="virtual-ports">Ports</label><input id="virtual-ports" placeholder="8000, 8443"></div>
              <div class="field span-4"><label for="virtual-snapshot-hint">Snapshot Hint</label><input id="virtual-snapshot-hint"></div>
              <div class="field span-8"><label for="virtual-notes">Notes</label><input id="virtual-notes" value="record observed virtual runtime state"></div>
            </div>
          </div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Real Provider Target Setup</h3><button class="action-btn" data-action="stage-virtual-target-setup-batch">Stage Batch</button></div>
            <div class="form-grid">
              <div class="field span-3"><label for="virtual-target-setup-scope">Scope</label><input id="virtual-target-setup-scope" value="all"></div>
              <div class="field span-3"><label for="virtual-target-setup-requested-by">Requested By</label><input id="virtual-target-setup-requested-by" value="dax"></div>
              <div class="field span-6"><label for="virtual-target-setup-reason">Reason</label><input id="virtual-target-setup-reason" value="prepare approved disposable real-provider targets for Dax lifecycle development"></div>
            </div>
          </div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Target Setup Result</h3><button class="action-btn" data-action="record-virtual-target-setup-result">Record Result</button></div>
            <div class="form-grid">
              <div class="field span-2"><label for="virtual-target-result-provider">Provider</label><input id="virtual-target-result-provider" value="docker"></div>
              <div class="field span-2"><label for="virtual-target-result-status">Status</label><input id="virtual-target-result-status" value="completed"></div>
              <div class="field span-2"><label for="virtual-target-result-executed-by">Executed By</label><input id="virtual-target-result-executed-by" value="dax"></div>
              <div class="field span-3"><label for="virtual-target-result-evidence">Evidence</label><input id="virtual-target-result-evidence" value="target verified with constrained network"></div>
              <div class="field span-3"><label for="virtual-target-result-next-step">Next Step</label><input id="virtual-target-result-next-step" value="run provider lifecycle smoke"></div>
            </div>
          </div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Execute Approved Target Setup</h3><button class="action-btn" data-action="execute-virtual-target-setup">Execute Setup</button></div>
            <div class="form-grid">
              <div class="field span-3"><label for="virtual-target-execute-provider">Provider</label><input id="virtual-target-execute-provider" value="docker"></div>
              <div class="field span-3"><label for="virtual-target-execute-executed-by">Executed By</label><input id="virtual-target-execute-executed-by" value="dax"></div>
              <div class="field span-3"><label for="virtual-target-execute-approved-by">Approved By</label><input id="virtual-target-execute-approved-by" value="sisko"></div>
            </div>
          </div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Virtual Lifecycle</h3><button class="action-btn" data-action="execute-virtual-lifecycle">Execute Lifecycle</button></div>
            <div class="form-grid">
              <div class="field span-3"><label for="virtual-lifecycle-resource-id">Resource ID</label><input id="virtual-lifecycle-resource-id" value="overseer-dax-disposable-proxy"></div>
              <div class="field span-2"><label for="virtual-lifecycle-action">Action</label><select id="virtual-lifecycle-action"><option value="inspect">inspect</option><option value="start">start</option><option value="stop">stop</option></select></div>
              <div class="field span-2"><label for="virtual-lifecycle-provider">Provider</label><input id="virtual-lifecycle-provider" placeholder="runtime adapter"></div>
              <div class="field span-2"><label for="virtual-lifecycle-executed-by">Executed By</label><input id="virtual-lifecycle-executed-by" value="dax"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Virtual Snapshot Request</h3><div class="actions"><button class="action-btn" data-action="stage-virtual-snapshot-request">Stage</button><button class="action-btn" data-action="approve-virtual-snapshot-request">Approve</button><button class="action-btn" data-action="execute-virtual-snapshot-request">Execute</button></div></div>
            <div class="form-grid">
              <div class="field span-6"><label for="snapshot-request-id">Request ID</label><input id="snapshot-request-id"></div>
              <div class="field span-6"><label for="snapshot-resource-id">Resource ID</label><input id="snapshot-resource-id" value="vm.local.resource"></div>
              <div class="field span-6"><label for="snapshot-name">Snapshot Name</label><input id="snapshot-name" value="before-maintenance"></div>
              <div class="field span-3"><label for="snapshot-requested-by">Requested By</label><input id="snapshot-requested-by" value="dax"></div>
              <div class="field span-3"><label for="snapshot-approved-by">Approved By</label><input id="snapshot-approved-by" value="sisko"></div>
              <div class="field span-3"><label for="snapshot-executed-by">Executed By</label><input id="snapshot-executed-by" value="dax"></div>
              <div class="field span-3"><label for="snapshot-provider">Provider</label><input id="snapshot-provider" value="local_fixture"></div>
              <div class="field span-12"><label for="snapshot-reason">Reason</label><input id="snapshot-reason" value="stage virtual snapshot before maintenance"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Virtual Restore Request</h3><div class="actions"><button class="action-btn" data-action="stage-virtual-restore-request">Stage</button><button class="action-btn" data-action="approve-virtual-restore-request">Approve</button><button class="action-btn" data-action="execute-virtual-restore-request">Execute</button></div></div>
            <div class="form-grid">
              <div class="field span-6"><label for="restore-virtual-request-id">Request ID</label><input id="restore-virtual-request-id"></div>
              <div class="field span-6"><label for="restore-virtual-resource-id">Resource ID</label><input id="restore-virtual-resource-id" value="vm.local.resource"></div>
              <div class="field span-6"><label for="restore-virtual-point">Restore Point</label><input id="restore-virtual-point" value="before-maintenance"></div>
              <div class="field span-3"><label for="restore-virtual-requested-by">Requested By</label><input id="restore-virtual-requested-by" value="dax"></div>
              <div class="field span-3"><label for="restore-virtual-approved-by">Approved By</label><input id="restore-virtual-approved-by" value="sisko"></div>
              <div class="field span-3"><label for="restore-virtual-executed-by">Executed By</label><input id="restore-virtual-executed-by" value="dax"></div>
              <div class="field span-3"><label for="restore-virtual-provider">Provider</label><input id="restore-virtual-provider" value="local_fixture"></div>
              <div class="field span-12"><label for="restore-virtual-reason">Reason</label><input id="restore-virtual-reason" value="stage virtual restore after failed change"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Virtual Destroy Request</h3><div class="actions"><button class="action-btn" data-action="stage-virtual-destroy-request">Stage</button><button class="action-btn" data-action="approve-virtual-destroy-request">Approve</button><button class="action-btn" data-action="execute-virtual-destroy-request">Execute</button></div></div>
            <div class="form-grid">
              <div class="field span-6"><label for="destroy-virtual-request-id">Request ID</label><input id="destroy-virtual-request-id"></div>
              <div class="field span-6"><label for="destroy-virtual-resource-id">Resource ID</label><input id="destroy-virtual-resource-id" value="vm.local.resource"></div>
              <div class="field span-3"><label for="destroy-virtual-requested-by">Requested By</label><input id="destroy-virtual-requested-by" value="dax"></div>
              <div class="field span-3"><label for="destroy-virtual-approved-by">Approved By</label><input id="destroy-virtual-approved-by" value="sisko"></div>
              <div class="field span-3"><label for="destroy-virtual-executed-by">Executed By</label><input id="destroy-virtual-executed-by" value="dax"></div>
              <div class="field span-3"><label for="destroy-virtual-provider">Provider</label><input id="destroy-virtual-provider" value="local_fixture"></div>
              <div class="field span-12"><label for="destroy-virtual-reason">Reason</label><input id="destroy-virtual-reason" value="stage virtual destroy after disposable target is no longer needed"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Image Vulnerability Scan</h3><div class="actions"><button class="action-btn" data-action="stage-image-scan">Stage</button><button class="action-btn" data-action="approve-image-scan">Approve</button><button class="action-btn" data-action="execute-image-scan">Execute</button></div></div>
            <div class="form-grid">
              <div class="field span-6"><label for="image-scan-request-id">Request ID</label><input id="image-scan-request-id"></div>
              <div class="field span-6"><label for="image-scan-image">Image</label><input id="image-scan-image" value="alpine:latest"></div>
              <div class="field span-3"><label for="image-scan-provider">Provider</label><input id="image-scan-provider" value="docker"></div>
              <div class="field span-3"><label for="image-scan-scanner">Scanner</label><input id="image-scan-scanner" value="trivy"></div>
              <div class="field span-3"><label for="image-scan-requested-by">Requested By</label><input id="image-scan-requested-by" value="dax"></div>
              <div class="field span-3"><label for="image-scan-approved-by">Approved By</label><input id="image-scan-approved-by" value="sisko"></div>
              <div class="field span-3"><label for="image-scan-executed-by">Executed By</label><input id="image-scan-executed-by" value="dax"></div>
              <div class="field span-9"><label for="image-scan-reason">Reason</label><input id="image-scan-reason" value="scan container image before production use"></div>
            </div>
          </div>
          <div class="panel span-12">${table("Claims", claims.items || [], ["id", "resource_id", "status", "claim_type", "next_step"], {fills: {id: (row) => claimFill(row.id), resource_id: (row) => resourceClaimFill(row.resource_id, row.owner_role || "dax")}, fillView: "claims"})}</div>
          <div class="panel span-12">${table("Cleanup Candidates", cleanup.items || [], ["id", "cleanup_action", "approval_required", "cleanup_next_step"], {fills: {id: (row) => cleanupFill(row)}, fillView: "claims"})}</div>
          <div class="panel span-12">${table("Virtual Runtime Evidence", virtualEvidence.items || [], ["resource_id", "kind", "state", "ports", "active_claims", "snapshot_status", "next_step"], {fills: {resource_id: (row) => resourceClaimFill(row.resource_id, "dax")}, fillView: "claims"})}</div>
          <div class="panel span-12">${table("Virtual Runtime Records", virtualOperations.runtime_records || virtualEvidence.runtime_records || [], ["resource_id", "kind", "state", "adapter", "ports", "next_step"], {fills: {resource_id: (row) => virtualRuntimeFill(row)}, fillView: "claims"})}</div>
          <div class="panel span-6">${table("Virtual Snapshot Requests", virtualOperations.snapshot_requests || virtualEvidence.snapshot_requests || [], ["id", "resource_id", "status", "approved_by", "next_step"], {fills: {id: (row) => virtualSnapshotFill(row), resource_id: (row) => virtualSnapshotFill(row)}, fillView: "claims"})}</div>
          <div class="panel span-6">${table("Virtual Restore Requests", virtualOperations.restore_requests || virtualEvidence.restore_requests || [], ["id", "resource_id", "restore_point", "status", "approved_by"], {fills: {id: (row) => virtualRestoreFill(row), resource_id: (row) => virtualRestoreFill(row)}, fillView: "claims"})}</div>
          <div class="panel span-6">${table("Virtual Destroy Requests", virtualOperations.destroy_requests || [], ["id", "resource_id", "status", "approved_by", "next_step"], {fills: {id: (row) => virtualDestroyFill(row), resource_id: (row) => virtualDestroyFill(row)}, fillView: "claims"})}</div>
          <div class="panel span-12">${table("Virtual Execution Records", virtualOperations.execution_records || [], ["id", "request_id", "resource_id", "action", "status", "provider", "manifest_path"])}</div>
          <div class="panel span-12">${table("Target Setup Requests", virtualOperations.target_setup_requests || [], ["id", "provider", "target_name", "status", "approval_required", "current_state", "proposed_state", "next_step"])}</div>
          <div class="panel span-12">${table("Runtime Adapter Availability", virtualEvidence.runtime_adapters || [], ["adapter", "available", "status", "mutation_boundary"])}</div>
          <div class="panel span-6">${kv("Virtual Capacity Summary", virtualEvidence.capacity_summary || {})}</div>
          <div class="panel span-6">${table("Provider Depth Coverage", virtualEvidence.provider_depth || [], ["provider", "registered_records", "inventory_rows", "snapshot_restore", "mutation_boundary", "next_step"])}</div>
          <div class="panel span-12">${table("Provider Policy Readiness", virtualEvidence.provider_policy || [], ["provider", "registered_records", "runtime_rows", "blocked_rows", "running_snapshot_policy", "non_disposable_policy", "approval_gate", "next_step"])}</div>
          <div class="panel span-12">${table("Runtime Mutation Readiness", virtualEvidence.runtime_readiness || [], ["provider", "resource_id", "state", "disposable", "running", "can_stage", "can_execute_live", "snapshot_policy", "restore_destroy_policy", "blockers"], {fills: {resource_id: (row) => resourceClaimFill(row.resource_id, "dax")}, fillView: "claims"})}</div>
          <div class="panel span-12">${table("Runtime Provider Inventory", virtualEvidence.runtime_inventory || [], ["provider", "resource_id", "kind", "state", "image", "cpu", "memory", "network", "virtual_size", "actual_size", "snapshots", "ports", "next_step"], {fills: {resource_id: (row) => resourceClaimFill(row.resource_id, "dax")}, fillView: "claims"})}</div>
          <div class="panel span-12">${table("Image Provenance Review", virtualEvidence.image_provenance || [], ["provider", "resource_id", "image", "state", "provenance", "next_step"], {fills: {resource_id: (row) => resourceClaimFill(row.resource_id, "dax"), image: (row) => imageScanFill(row)}, fillView: "claims"})}</div>
          <div class="panel span-6">${table("Image Scanner Adapters", imageScans.scanner_adapters || virtualEvidence.image_scanner_adapters || [], ["scanner", "available", "status", "next_step"])}</div>
          <div class="panel span-6">${table("Image Scan Requests", imageScans.scan_requests || virtualEvidence.image_scan_requests || [], ["id", "image", "scanner", "status", "approved_by", "next_step"], {fills: {id: (row) => imageScanFill(row), image: (row) => imageScanFill(row)}, fillView: "claims"})}</div>
          <div class="panel span-12">${table("Image Scan Results", imageScans.scan_results || virtualEvidence.image_scan_results || [], ["id", "image", "status", "critical", "high", "medium", "low", "unknown", "next_step"], {fills: {id: (row) => imageScanFill(row), image: (row) => imageScanFill(row)}, fillView: "claims"})}</div>
          <div class="panel span-6">${table("Port Pool Evidence", virtualEvidence.port_pool || [], ["port", "owner_count", "status", "owners"])}</div>
          <div class="panel span-6">${table("Virtual Cleanup Evidence", virtualEvidence.cleanup || [], ["claim_id", "resource_id", "status", "next_step"], {fills: {claim_id: (row) => cleanupFill({id: row.claim_id})}, fillView: "claims"})}</div>
          <div class="panel span-12">${table("Virtual Runtime Inventory", operations.virtual_runtime || [], ["resource_id", "kind", "state", "ports", "active_claims", "cleanup_candidates", "next_step"], {fills: {resource_id: (row) => resourceClaimFill(row.resource_id, "dax")}, fillView: "claims"})}</div>
          ${officerPanel("dax", "Checkout conflict", "Deconflict a claim, lease, lock, or cleanup request.")}
        </div>`;
    }
    function renderSecurity() {
      const security = state.data.security || {};
      const host = security.host_security || {};
      const plans = (security.protective_plans || {}).items || [];
      const listenerQueue = state.data.listenerReviewQueue || {};
      const sourceQueue = state.data.sourceReviewQueue || {};
      const securityEvidence = state.data.securityEvidence || {};
      const keyBroker = state.data.keyBroker || {};
      const identityEvidence = state.data.identityEvidence || {};
      const identityRotationRequests = state.data.identityRotationRequests || {};
      const identityRotationReadiness = state.data.identityRotationReadiness || {};
      const operations = state.data.operations || {};
      const auth = state.data.authorizations || {};
      const readiness = state.data.readiness || {};
      document.getElementById("security").innerHTML = `
        <div class="grid">
          ${stationIntro("Odo", "Security Board", "Host inspection, source review, and protective action staging.", ["listeners", "source review", "IDS package"])}
          <div class="section-head"><h3>Security Actions</h3><div class="actions"><button class="action-btn" data-action="inspect-host">Inspect Host</button><button class="action-btn" data-action="advance-odo-security">Advance Odo Review</button><button class="action-btn" data-action="plan-listener-queue-remediations">Plan Listener Queue</button></div></div>
          ${metric("Alerts", security.alerts, "security", "span-3", security.alerts ? "bad" : "good", "audit")}
          ${metric("High", host.high_findings, "findings", "span-3", host.high_findings ? "bad" : "good", "security")}
          ${metric("Warning", host.warning_findings, "findings", "span-3", host.warning_findings ? "warn" : "good", "security")}
          ${metric("Plans", (security.protective_plans || {}).total, "protective", "span-3", "", "admin")}
          ${authorizationDecisionBoard(auth, readiness)}
          <div class="panel span-6">
            <div class="toolbar"><h3>Plan Remediation</h3><button class="action-btn" data-action="plan-host-security-remediation">Plan</button></div>
            <div class="form-grid">
              <div class="field span-6"><label for="security-listener">Listener</label><input id="security-listener" value="0.0.0.0:22"></div>
              <div class="field span-3"><label for="security-remediation-action">Action</label><input id="security-remediation-action" value="deny_tcp"></div>
              <div class="field span-3"><label for="security-plan-id">Plan ID</label><input id="security-plan-id"></div>
              <div class="field span-4"><label for="security-snapshot-id">Snapshot ID</label><input id="security-snapshot-id"></div>
              <div class="field span-8"><label for="security-remediation-reason">Reason</label><input id="security-remediation-reason" value="review exposed listener"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Source Review</h3><button class="action-btn" data-action="record-source-review">Record</button></div>
            <div class="form-grid">
              <div class="field span-4"><label for="source-remote-address">Remote Address</label><input id="source-remote-address" value="192.0.2.10"></div>
              <div class="field span-4"><label for="source-listener">Listener</label><input id="source-listener" value="0.0.0.0:22"></div>
              <div class="field span-4"><label for="source-disposition">Disposition</label><select id="source-disposition">${sourceDispositionOptions()}</select></div>
              <div class="field span-4"><label for="source-review-id">Review ID</label><input id="source-review-id"></div>
              <div class="field span-4"><label for="source-snapshot-id">Snapshot ID</label><input id="source-snapshot-id"></div>
              <div class="field span-4"><label for="source-reviewed-by">Reviewed By</label><input id="source-reviewed-by" value="odo"></div>
              <div class="field span-12"><label for="source-rationale">Rationale</label><input id="source-rationale" value="pending Odo review"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Source Block</h3><button class="action-btn" data-action="plan-source-block">Plan Block</button></div>
            <div class="form-grid">
              <div class="field span-4"><label for="source-block-review-id">Review ID</label><input id="source-block-review-id"></div>
              <div class="field span-4"><label for="source-block-action">Action</label><input id="source-block-action" value="block_ip"></div>
              <div class="field span-4"><label for="source-block-plan-id">Plan ID</label><input id="source-block-plan-id"></div>
              <div class="field span-12"><label for="source-block-reason">Reason</label><input id="source-block-reason" value="hostile source reviewed by Odo"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Firewall Policy Enforcement</h3><button class="action-btn" data-action="stage-firewall-policy-enforcement">Stage Enforcement</button></div>
            <div class="form-grid">
              <div class="field span-3"><label for="firewall-rule-index">Rule Index</label><input id="firewall-rule-index" type="number" min="0" value="0"></div>
              <div class="field span-5"><label for="firewall-plan-id">Plan ID</label><input id="firewall-plan-id"></div>
              <div class="field span-4"><label for="firewall-requested-by">Requested By</label><input id="firewall-requested-by" value="odo_firewall"></div>
              <div class="field span-12"><label for="firewall-enforcement-reason">Reason</label><input id="firewall-enforcement-reason" value="stage desired firewall policy enforcement for IDS review"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Execute Firewall Fixture</h3><button class="action-btn" data-action="execute-firewall-change">Execute Fixture</button></div>
            <div class="form-grid">
              <div class="field span-5"><label for="firewall-execute-plan-id">Plan ID</label><input id="firewall-execute-plan-id" value="admin.host-security.firewall"></div>
              <div class="field span-3"><label for="firewall-execute-by">Executed By</label><input id="firewall-execute-by" value="odo_firewall"></div>
              <div class="field span-4"><label for="firewall-execute-mode">Mode</label><select id="firewall-execute-mode"><option value="local_fixture">local_fixture</option><option value="live">live</option></select></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Identity Rotation Request</h3><div class="actions"><button class="action-btn" data-action="stage-identity-rotation-request">Stage Request</button><button class="action-btn" data-action="approve-identity-rotation-request">Approve</button><button class="action-btn" data-action="execute-identity-rotation-request">Execute Fixture</button></div></div>
            <div class="form-grid">
              <div class="field span-4"><label for="identity-rotation-subject">Subject</label><input id="identity-rotation-subject" value="local secret"></div>
              <div class="field span-3"><label for="identity-rotation-subject-type">Type</label><select id="identity-rotation-subject-type">${identitySubjectTypeOptions()}</select></div>
              <div class="field span-2"><label for="identity-rotation-urgency">Urgency</label><select id="identity-rotation-urgency">${riskOptions()}</select></div>
              <div class="field span-3"><label for="identity-rotation-requested-by">Requested By</label><input id="identity-rotation-requested-by" value="odo"></div>
              <div class="field span-5"><label for="identity-rotation-request-id">Request ID</label><input id="identity-rotation-request-id"></div>
              <div class="field span-3"><label for="identity-rotation-approved-by">Approved By</label><input id="identity-rotation-approved-by" value="sisko"></div>
              <div class="field span-2"><label for="identity-rotation-executed-by">Executed By</label><input id="identity-rotation-executed-by" value="odo"></div>
              <div class="field span-2"><label for="identity-rotation-execute-mode">Mode</label><select id="identity-rotation-execute-mode"><option value="local_fixture">local_fixture</option><option value="live">live</option></select></div>
              <div class="field span-12"><label for="identity-rotation-reason">Reason</label><input id="identity-rotation-reason" value="stage identity or secret rotation review"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>IDS Review Manual Override</h3><div class="actions"><button class="action-btn" data-action="prepare-ids-review-package">Prepare</button><button class="action-btn" data-action="export-ids-review-prompt">Export</button><button class="action-btn" data-action="dispatch-ids-review-package">Dispatch</button><button class="action-btn" data-action="record-ids-review-result">Record</button></div></div>
            <div class="form-grid">
              <div class="field span-4"><label for="ids-plan-id">Plan ID</label><input id="ids-plan-id"></div>
              <div class="field span-4"><label for="ids-package-id">Package ID</label><input id="ids-package-id"></div>
              <div class="field span-4"><label for="ids-source-review-id">Source Review</label><input id="ids-source-review-id"></div>
              <div class="field span-3"><label for="ids-requested-by">Requested By</label><input id="ids-requested-by" value="odo_ids"></div>
              <div class="field span-3"><label for="ids-export-package-id">Export Package</label><input id="ids-export-package-id"></div>
              <div class="field span-3"><label for="ids-dispatch-package-id">Dispatch Package</label><input id="ids-dispatch-package-id"></div>
              <div class="field span-3"><label for="ids-dispatched-by">Dispatched By</label><input id="ids-dispatched-by" value="odo_ids"></div>
              <div class="field span-4"><label for="ids-owner-thread">Owner Thread</label><input id="ids-owner-thread"></div>
              <div class="field span-4"><label for="ids-result-package-id">Result Package</label><input id="ids-result-package-id"></div>
              <div class="field span-4"><label for="ids-result-status">Result Status</label><select id="ids-result-status">${idsReviewStatusOptions()}</select></div>
              <div class="field span-4"><label for="ids-reviewed-by">Reviewed By</label><input id="ids-reviewed-by" value="odo_ids"></div>
              <div class="field span-8"><label for="ids-advisory-result">Advisory Result</label><input id="ids-advisory-result" value="accepted staged package"></div>
            </div>
          </div>
          <div class="panel span-8">${table("Protective Plans", plans, ["id", "kind", "target", "approved", "canceled"], {fills: {id: (row) => adminPlanFill(row.id)}, fillView: "admin"})}</div>
          <div class="panel span-4">${kv("IDS Review", security.ids_review || {})}</div>
          <div class="panel span-12">${table("Listener Review Queue", listenerQueue.items || [], ["listener", "bind_scope", "severity", "queue_status", "plan_id", "next_step"], {fills: {listener: (row) => listenerFill(row), plan_id: (row) => adminPlanFill(row.plan_id)}, fillView: "security"})}</div>
          <div class="panel span-12">${table("Source Review Queue", sourceQueue.items || [], ["remote_address", "listener", "source_scope", "disposition", "queue_status", "next_step"], {fills: {remote_address: (row) => sourceReviewFill(row), listener: (row) => sourceReviewFill(row)}, fillView: "security"})}</div>
          <div class="panel span-6">${table("Security Baseline Checks", securityEvidence.baseline_checks || [], ["check", "status", "evidence", "next_step"])}</div>
          <div class="panel span-6">${table("Firewall Provenance", securityEvidence.firewall_provenance || [], ["name", "status", "exit_code", "summary"])}</div>
          <div class="panel span-12">${table("Firewall Policy Diff", securityEvidence.firewall_policy_diff || [], ["index", "action", "port", "status", "next_step", "rule"], {fills: {index: (row) => firewallPolicyFill(row), rule: (row) => firewallPolicyFill(row)}, fillView: "security"})}</div>
          <div class="panel span-12">${table("Listener Exposure Evidence", securityEvidence.listener_exposure || [], ["id", "severity", "summary", "recommended_action"], {fills: {id: (row) => ({ "op-record-id": `ops.security.${row.id || "finding"}`, "op-kind": "security_baseline", "op-owner": "odo", "op-status": "staged", "op-severity": row.severity === "high" ? "high" : "medium", "op-subject": row.summary || "Security exposure review", "op-summary": row.evidence || "", "op-next-step": row.recommended_action || "stage security review" })}, fillView: "overview"})}</div>
          <div class="panel span-12">${table("Protective Plan Provenance", securityEvidence.protective_plan_provenance || [], ["id", "kind", "target", "approved", "canceled", "rollback"], {fills: {id: (row) => adminPlanFill(row.id)}, fillView: "admin"})}</div>
          <div class="panel span-6">${table("Security Baseline Drift", operations.security_drift || [], ["check", "status", "evidence", "next_step"])}</div>
          <div class="panel span-6">${table("Identity And Secrets", [operations.identity_access || {}], ["local_users", "local_groups", "service_accounts", "public_ssh_keys", "next_step"])}</div>
          <div class="panel span-6">${kv("Key Broker Policy", {
            broker_root: keyBroker.broker_root,
            secret_policy: keyBroker.secret_policy,
            pending_approval: keyBroker.summary?.pending_approval,
            active_grants: keyBroker.summary?.active_grants
          })}</div>
          <div class="panel span-6">${table("Key Providers", keyBroker.providers || [], ["id", "provider_kind", "enabled", "allowed_subjects", "allowed_scopes"])}</div>
          <div class="panel span-6">${table("Key Requests", keyBroker.requests || [], ["id", "provider_id", "subject", "status", "risk_level", "ttl_minutes"])}</div>
          <div class="panel span-6">${table("Key Grants", keyBroker.grants || [], ["id", "provider_id", "subject", "status", "expires_at", "revoked_at"])}</div>
          <div class="panel span-12">${table("Identity Access Review", identityEvidence.users || [], ["user", "uid", "account_type", "home", "login_shell"])}</div>
          <div class="panel span-6">${table("SSH Key Custody", identityEvidence.ssh_keys || [], ["path", "kind", "fingerprint", "status"], {fills: {path: (row) => identityRotationFill({...row, subject_type: "ssh_key"})}, fillView: "security"})}</div>
          <div class="panel span-6">${table("Secret File Custody", identityEvidence.secret_files || [], ["path", "status", "content"], {fills: {path: (row) => identityRotationFill({...row, subject_type: "secret"})}, fillView: "security"})}</div>
          <div class="panel span-12">${table("Rotation Reminders", identityEvidence.rotation_reminders || [], ["area", "items", "next_step"], {fills: {area: (row) => identityRotationFill(row)}, fillView: "security"})}</div>
          <div class="panel span-12">${table("Identity Rotation Requests", identityRotationRequests.requests || identityEvidence.rotation_requests || [], ["id", "subject_type", "subject", "urgency", "status", "approval_required", "next_step"], {fills: {subject: (row) => identityRotationFill(row), id: (row) => identityRotationFill(row)}, fillView: "security"})}</div>
          <div class="panel span-12">${table("Identity Rotation Readiness", identityRotationReadiness.items || [], ["request_id", "subject_type", "status", "readiness_state", "can_execute", "live_execution_available", "blockers", "next_step"], {fills: {request_id: (row) => identityRotationFill({subject: row.subject, subject_type: row.subject_type})}, fillView: "security"})}</div>
          <div class="panel span-12">${table("Network Gateway Analysis", [operations.network || {}], ["interfaces", "routes", "dns_servers", "listener_rows", "gateway_routes", "next_step"])}</div>
          <div class="section-head"><h3>Odo Security Team</h3><div class="actions"><span class="pill">reports to Odo</span></div></div>
          ${officerPanel("odo", "Security investigation", "Investigate traffic, exposed listeners, intrusion signals, or protective actions.")}
          ${officerPanel("odo_ids", "IDS advisory review", "Review IDS/firewall advisory packages, return accepted or revision results, and report blockers to Odo.")}
          ${officerPanel("odo_firewall", "Firewall management", "Stage firewall remediation plans, prepare rollback and verification evidence, and hand IDS review work to Odo IDS.")}
        </div>`;
    }
    function renderHealth() {
      const health = state.data.health || {};
      const healthSummary = state.data.healthSummary || {};
      const serviceEvidence = state.data.serviceEvidence || {};
      const codexUsage = state.data.codexUsage || {};
      const codexWindows = (codexUsage.rate_limits || []).flatMap((limit) =>
        (limit.windows || []).map((window) => ({
          limit: limit.limit_name || limit.limit_id,
          plan: limit.plan_type,
          window: window.name,
          used_percent: window.used_percent,
          remaining_percent: window.remaining_percent,
          resets_at: window.resets_at
        }))
      );
      const codexAccount = codexUsage.account_usage || {};
      const journalAccess = serviceEvidence.journal_access || {};
      const observabilityTrends = state.data.observabilityTrends || {};
      const metricHistory = state.data.metricHistory || {};
      const performanceHistory = state.data.performanceHistory || {};
      const runtime = state.data.runtime || {};
      const operations = state.data.operations || {};
      document.getElementById("health").innerHTML = `
        <div class="grid">
          ${stationIntro("Julian", "Diagnostics Lab", "Service health, probe failures, and runtime freshness.", ["probes", "MCP checks", "HTML and JSON"])}
          <div class="section-head"><h3>Health Actions</h3><div class="actions"><button class="action-btn" data-action="run-health-probes">Run Probes</button></div></div>
          ${metric("Targets", health.targets, "registered", "span-3", "", "health")}
          ${metric("Unhealthy", health.unhealthy, "targets", "span-3", health.unhealthy ? "bad" : "good", "health")}
          ${metric("Recovery", health.recovery_required, "required", "span-3", health.recovery_required ? "warn" : "good", "health")}
          ${metric("Failures", health.latest_failures, "latest", "span-3", health.latest_failures ? "bad" : "good", "audit")}
          ${metric("Codex Capacity", codexUsage.minimum_remaining_percent, "% remaining", "span-3", codexUsage.posture === "critical" ? "bad" : codexUsage.posture === "conserve" ? "warn" : "good", "health")}
          ${metric("Codex Posture", codexUsage.posture, codexUsage.confidence || "unknown confidence", "span-3", codexUsage.available ? "good" : "bad", "health")}
          <div class="panel span-6">${kv("Codex Usage Status", {
            available: codexUsage.available,
            observed_at: codexUsage.observed_at,
            recommendation: codexUsage.recommendation,
            next_step: codexUsage.next_step
          })}</div>
          <div class="panel span-6">${kv("Codex Account Usage", {
            lifetime_tokens: codexAccount.lifetime_tokens,
            peak_daily_tokens: codexAccount.peak_daily_tokens,
            longest_running_turn_seconds: codexAccount.longest_running_turn_seconds,
            current_streak_days: codexAccount.current_streak_days
          })}</div>
          <div class="panel span-12">${table("Codex Usage Windows", codexWindows, ["limit", "plan", "window", "used_percent", "remaining_percent", "resets_at"])}</div>
          <div class="panel span-6">${kv("Runtime Heartbeat", {
            service: runtime.service?.service_name,
            freshness: runtime.service?.freshness?.status,
            tick_count: runtime.service?.tick_count,
            last_tick_at: runtime.service?.last_tick_at,
            next_step: runtime.service?.freshness?.next_step
          })}</div>
          <div class="panel span-6">${kv("Host Inspection Freshness", {
            enabled: runtime.host_inspection?.enabled,
            freshness: runtime.host_inspection?.freshness?.status,
            high_findings: runtime.host_inspection?.high_findings,
            warning_findings: runtime.host_inspection?.warning_findings,
            latest_captured_at: runtime.host_inspection?.latest_captured_at,
            next_step: runtime.host_inspection?.freshness?.next_step
          })}</div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Register Target</h3><button class="action-btn" data-action="register-health-target">Record Target</button></div>
            <div class="form-grid">
              <div class="field span-2"><label for="health-target-id">Target ID</label><input id="health-target-id" value="health.local.service"></div>
              <div class="field span-2"><label for="health-resource-id">Resource ID</label><input id="health-resource-id" value="svc.systemd-user.overseer-api"></div>
              <div class="field span-2"><label for="health-name">Name</label><input id="health-name" value="Local Service"></div>
              <div class="field span-2"><label for="health-probe-type">Probe</label><select id="health-probe-type">${probeTypeOptions()}</select></div>
              <div class="field span-2"><label for="health-expected-status">Expected HTTP</label><input id="health-expected-status" type="number" min="100" max="599"></div>
              <div class="field span-2"><label for="health-expected-content-type">Content Type</label><input id="health-expected-content-type"></div>
              <div class="field span-6"><label for="health-target">Target</label><input id="health-target" value="http://127.0.0.1:8766/health"></div>
            </div>
          </div>
          <div class="panel span-12">
            <div class="toolbar"><h3>System Journal Access Request</h3><button class="action-btn" data-action="stage-journal-access-request">Stage Request</button></div>
            <div class="form-grid">
              <div class="field span-3"><label for="journal-resource-id">Resource ID</label><input id="journal-resource-id" value="svc.system.service"></div>
              <div class="field span-3"><label for="journal-unit">Unit</label><input id="journal-unit" value="example.service"></div>
              <div class="field span-2"><label for="journal-requested-by">Requested By</label><input id="journal-requested-by" value="julian"></div>
              <div class="field span-4"><label for="journal-reason">Reason</label><input id="journal-reason" value="system journal access needed for service diagnosis"></div>
            </div>
          </div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Execute Journal Capture</h3><button class="action-btn" data-action="execute-journal-access-request">Execute Capture</button></div>
            <div class="form-grid">
              <div class="field span-4"><label for="journal-execute-record-id">Record ID</label><input id="journal-execute-record-id" value="ops.service.journal-access.svc.system.service"></div>
              <div class="field span-2"><label for="journal-execute-by">Executed By</label><input id="journal-execute-by" value="julian"></div>
              <div class="field span-2"><label for="journal-execute-lines">Lines</label><input id="journal-execute-lines" type="number" min="1" max="200" value="50"></div>
              <div class="field span-4"><label for="journal-execute-since">Since</label><input id="journal-execute-since" value="24 hours ago"></div>
            </div>
          </div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Metric History Capture</h3><button class="action-btn" data-action="capture-metric-history">Capture Metrics</button></div>
            <div class="form-grid">
              <div class="field span-3"><label for="metric-history-id">Snapshot ID</label><input id="metric-history-id" placeholder="optional"></div>
              <div class="field span-2"><label for="metric-history-requested-by">Requested By</label><input id="metric-history-requested-by" value="julian"></div>
              <div class="field span-2"><label for="metric-history-retention">Retention</label><input id="metric-history-retention" type="number" min="1" value="250"></div>
              <div class="field span-5"><label for="metric-history-notes">Notes</label><input id="metric-history-notes" value="capture retained observability trends"></div>
            </div>
          </div>
          <div class="panel span-12">${table("Health Targets", healthSummary.summaries || [], ["resource_id", "name", "status", "recovery_required", "error"], {fills: {resource_id: (row) => ({ "health-resource-id": row.resource_id, "health-name": row.name || "" })}, fillView: "health"})}</div>
          <div class="panel span-12">${table("Service Evidence", serviceEvidence.items || [], ["resource_id", "unit", "health", "health_error", "executions", "next_step"], {fills: {resource_id: (row) => serviceEvidenceFill(row)}, fillView: "health"})}</div>
          <div class="panel span-6">${table("Service Dependency Nodes", (serviceEvidence.dependency_graph || {}).nodes || [], ["resource_id", "known", "owner_domain", "risk", "health"], {fills: {resource_id: (row) => ({ "health-resource-id": row.resource_id })}, fillView: "health"})}</div>
          <div class="panel span-6">${table("Service Dependency Edges", (serviceEvidence.dependency_graph || {}).edges || [], ["from", "to", "known", "owner_domain", "health", "risk"], {fills: {from: (row) => ({ "health-resource-id": row.from }), to: (row) => ({ "health-resource-id": row.to })}, fillView: "health"})}</div>
          <div class="panel span-6">${kv("Journal Access Status", {
            journalctl_available: journalAccess.journalctl_available,
            user_journal_access: journalAccess.user_journal_access?.available,
            system_journal_access: journalAccess.system_journal_access?.available,
            next_step: journalAccess.next_step
          })}</div>
          <div class="panel span-6">${table("System Journal Requests", journalAccess.system_review_requests || [], ["resource_id", "unit", "scope", "approval_required", "status", "next_step"], {fills: {resource_id: (row) => journalAccessFill(row), unit: (row) => journalAccessFill(row)}, fillView: "health"})}</div>
          <div class="panel span-6">${table("Service Validation Checklist", serviceValidationRows(serviceEvidence.items || []), ["resource_id", "step", "status"], {fills: {resource_id: (row) => serviceEvidenceFill(row)}, fillView: "health"})}</div>
          <div class="panel span-6">${table("Redacted Service Logs", serviceLogRows(serviceEvidence.items || []), ["resource_id", "target_id", "path", "readable", "lines"], {fills: {resource_id: (row) => serviceEvidenceFill(row)}, fillView: "health"})}</div>
          <div class="panel span-12">${table("Journal Excerpts", serviceJournalRows(serviceEvidence.items || []), ["resource_id", "unit", "available", "exit_code", "error"], {fills: {resource_id: (row) => serviceEvidenceFill(row)}, fillView: "health"})}</div>
          <div class="panel span-12">${table("System Journal Captures", systemJournalCaptureRows(serviceEvidence.items || []), ["resource_id", "id", "unit", "status", "captured_at", "captured_lines", "capture_path"], {fills: {resource_id: (row) => serviceEvidenceFill(row), id: (row) => ({ "journal-execute-record-id": row.record_id || "" })}, fillView: "health"})}</div>
          <div class="panel span-6">${table("Host Resources", [operations.host_resources || {}], ["load_1m", "memory_available_mb", "root_free_gb", "processes", "thermal_zones"])}</div>
          <div class="panel span-6">${table("Log Evidence", operations.log_evidence || [], ["target_id", "resource_id", "kind", "status", "latest_evidence"])}</div>
          <div class="panel span-12">${table("Service Details", operations.service_details || [], ["resource_id", "name", "state", "health", "targets", "dependencies", "admin_plans"], {fills: {resource_id: (row) => ({ "health-resource-id": row.resource_id, "health-name": row.name || "" })}, fillView: "health"})}</div>
          <div class="panel span-12">${table("Service Actions", operations.service_actions || [], ["resource_id", "action", "status", "approval", "existing_plans"], {fills: {resource_id: (row) => ({ "admin-target": row.resource_id, "admin-kind": "user_service_restart", "admin-reason": `stage ${row.action} for ${row.resource_id}` })}, fillView: "admin"})}</div>
          <div class="panel span-12">${table("Observability And Performance", operations.observability || [], ["resource_id", "status", "recovery_required", "evidence", "history_records"], {fills: {resource_id: (row) => ({ "health-resource-id": row.resource_id })}, fillView: "health"})}</div>
          <div class="panel span-12">${table("Health Trend History", observabilityTrends.resource_trends || [], ["resource_id", "samples", "healthy", "unhealthy", "latest_status", "error_rate_status"], {fills: {resource_id: (row) => ({ "health-resource-id": row.resource_id })}, fillView: "health"})}</div>
          <div class="panel span-12">${table("Metric History Snapshots", metricHistory.snapshots || [], ["id", "captured_at", "requested_by", "resource_count", "attention_resources", "next_step"], {fills: {id: (row) => metricHistoryFill(row)}, fillView: "health"})}</div>
          <div class="panel span-12">${table("Performance Regression History", performanceHistory.reports || [], ["report", "status", "operator_performance_status", "operator_performance_seconds", "operator_functional_seconds", "project_regression_seconds", "next_step"])}</div>
          <div class="panel span-12">${table("Host Snapshot Trend", observabilityTrends.host_snapshot_trends || [], ["snapshot_id", "captured_at", "hostname", "observation_count"])}</div>
          ${officerPanel("julian", "Service health issue", "Diagnose MCP, HTTP, HTML, JSON, process, or probe failures.")}
        </div>`;
    }
    function probeTypeOptions() {
      return ["json", "http", "https", "mcp", "html", "process", "command", "log", "manual"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function resourceTypeOptions() {
      return ["service", "virtual_asset", "physical_asset", "usage_limited_service", "maintenance_target", "security_surface", "composite"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function ownerOptions() {
      return ["julian", "dax", "kira", "obrien", "odo", "odo_ids", "odo_firewall", "quark", "sisko", "ezri"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function riskOptions() {
      return ["low", "medium", "high", "critical"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function claimTypeOptions() {
      return ["observation", "checkout", "lock", "lease", "hold", "quarantine"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function adminKindOptions() {
      return ["user_service_restart", "apt_install", "apt_update", "apt_upgrade", "firmware_update", "flatpak_install", "npm_global_install", "docker_compose_update", "storage_mount_test", "firewall_allow_tcp", "firewall_deny_tcp", "block_ip"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function firmwareBlockerRows(items) {
      return (items || []).filter((item) => item.blocker_type).map((item) => ({
        device: item.device,
        blocker_type: item.blocker_type,
        blocker_resolution: item.blocker_resolution,
        safe_preflight: (item.safe_preflight || []).join("; ")
      }));
    }
    function sourceDispositionOptions() {
      return ["needs_review", "expected", "benign", "suspicious", "hostile"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function identitySubjectTypeOptions() {
      return ["secret", "ssh_key", "api_key", "service_account", "user", "group"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function idsReviewStatusOptions() {
      return ["accepted", "revision_required"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function operationKindOptions() {
      return ["incident", "maintenance_window", "service_detail", "security_baseline", "network_route", "storage_backup", "physical_lifecycle", "virtual_runtime", "observability_trend", "usage_cost", "compliance_drift", "document_freshness", "identity_access"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function operationStatusOptions() {
      return ["open", "triaged", "staged", "waiting_approval", "in_progress", "verified", "closed", "blocked"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function maintenanceScheduleStatusOptions() {
      return ["active", "paused", "retired"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function advisorySourceOptions() {
      return ["nvd", "debian", "both"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function operationWorkflowOptions(templates) {
      return (templates || []).map((item) => `<option value="${safe(item.id)}">${safe(item.id)}</option>`).join("");
    }
    function policyQuestionControls(questions) {
      return (questions || []).map((question) => {
        const options = (question.options || []).map((option) => {
          const selected = String(option) === String(question.default) ? " selected" : "";
          return `<option value="${safe(option)}"${selected}>${safe(option)}</option>`;
        }).join("");
        return `<div class="field span-6"><label for="policy-answer-${safe(question.id)}">${safe(question.prompt)}</label><select id="policy-answer-${safe(question.id)}">${options}</select></div>`;
      }).join("");
    }
    function typedPolicyAnswer(question, rawValue) {
      const sample = (question.options || [])[0];
      if (typeof sample === "boolean") return rawValue === "true";
      return rawValue;
    }
    function value(id) {
      const element = document.getElementById(id);
      return element ? element.value.trim() : "";
    }
    function splitList(raw) {
      return (raw || "").split(/[,\\n]/).map((item) => item.trim()).filter(Boolean);
    }
    function applyFill(encoded) {
      if (!encoded) return;
      const fields = JSON.parse(encoded);
      Object.entries(fields).forEach(([id, val]) => {
        const element = document.getElementById(id);
        if (element) element.value = val ?? "";
      });
    }
    function renderUsage() {
      const usage = state.data.usage || {};
      const operations = state.data.operations || {};
      const usageEvidence = state.data.usageEvidence || {};
      const remoteTesting = state.data.remoteTesting || usageEvidence.remote_testing || {};
      const adapterStatus = remoteTesting.adapter_status || {};
      const queueCounts = remoteTesting.queue_counts || {};
      document.getElementById("usage").innerHTML = `
        <div class="grid">
          ${stationIntro("Quark", "Quota Exchange", "Usage-limited services, renewal windows, continuation dispatch, and remote test leases.", ["API-keyed MCP", "renewals", "Tank/MSI"])}
          <div class="section-head"><h3>Usage Actions</h3><div class="actions"><button class="action-btn" data-action="discover-codex-threads">Discover Codex Threads</button><button class="action-btn" data-action="dispatch-usage-continuations">Dispatch Ready</button><button class="action-btn" data-action="collect-remote-test-results">Collect Remote Results</button></div></div>
          ${metric("Limits", usage.limits, "tracked", "span-3", "", "usage")}
          ${metric("Available", usage.available, "limits", "span-3", "good", "usage")}
          ${metric("Exhausted", usage.exhausted, "limits", "span-3", usage.exhausted ? "warn" : "good", "usage")}
          ${metric("Low Confidence", usage.low_confidence, "limits", "span-3", usage.low_confidence ? "warn" : "good", "usage")}
          ${metric("Remote Queue", adapterStatus.status || "unknown", "Tank/MSI", "span-3", adapterStatus.status === "configured" ? "good" : "warn", "usage")}
          ${metric("Pending Tests", queueCounts.pending ?? 0, "queued", "span-3", queueCounts.pending ? "pending" : "good", "usage")}
          ${metric("Active Leases", (remoteTesting.active_leases || []).length, "remote testing", "span-3", (remoteTesting.active_leases || []).length ? "good" : "inactive", "usage")}
          ${metric("Results", (remoteTesting.recent_results || []).length, "redacted", "span-3", "", "usage")}
          <div class="panel span-6">
            <div class="toolbar"><h3>Record Limit</h3><button class="action-btn" data-action="record-usage-limit">Record Limit</button></div>
            <div class="form-grid">
              <div class="field span-6"><label for="usage-limit-id">Limit ID</label><input id="usage-limit-id" value="limit.mcp.api.calls.daily"></div>
              <div class="field span-6"><label for="usage-resource-id">Resource ID</label><input id="usage-resource-id" value="svc.mcp.api-keyed"></div>
              <div class="field span-4"><label for="usage-kind">Kind</label><input id="usage-kind" value="daily_quota"></div>
              <div class="field span-4"><label for="usage-window">Window</label><input id="usage-window" value="daily"></div>
              <div class="field span-2"><label for="usage-capacity">Capacity</label><input id="usage-capacity" type="number" min="0" value="1000"></div>
              <div class="field span-2"><label for="usage-remaining">Remaining</label><input id="usage-remaining" type="number" min="0" value="0"></div>
              <div class="field span-4"><label for="usage-confidence">Confidence</label><input id="usage-confidence" type="number" min="0" max="1" step="0.01" value="1"></div>
              <div class="field span-4"><label for="usage-resets-at">Resets At</label><input id="usage-resets-at" placeholder="2026-07-19T18:00:00+00:00"></div>
              <div class="field span-4"><label for="usage-observed-at">Observed At</label><input id="usage-observed-at" placeholder="optional"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Request Continuation</h3><button class="action-btn" data-action="request-usage-continuation">Request</button></div>
            <div class="form-grid">
              <div class="field span-6"><label for="usage-request-id">Request ID</label><input id="usage-request-id" value="work.mcp.api.continue"></div>
              <div class="field span-6"><label for="usage-request-limit-id">Limit ID</label><input id="usage-request-limit-id" value="limit.mcp.api.calls.daily"></div>
              <div class="field span-6"><label for="usage-request-resource-id">Resource ID</label><input id="usage-request-resource-id" value="svc.mcp.api-keyed"></div>
              <div class="field span-6"><label for="usage-owner-thread">Owner Thread</label><input id="usage-owner-thread" value="thread.mcp.api-work"></div>
              <div class="field span-3"><label for="usage-requested-units">Units</label><input id="usage-requested-units" type="number" min="0" value="1"></div>
              <div class="field span-3"><label for="usage-risk">Risk</label><select id="usage-risk">${riskOptions()}</select></div>
              <div class="field span-6"><label for="usage-requested-by">Requested By</label><input id="usage-requested-by" value="quark"></div>
              <div class="field span-12"><label for="usage-intent">Intent</label><input id="usage-intent" value="continue queued MCP API-keyed work after quota renewal"></div>
              <div class="field span-6"><label for="usage-earliest-start">Earliest Start</label><input id="usage-earliest-start" placeholder="optional"></div>
              <div class="field span-6"><label for="usage-deadline">Deadline</label><input id="usage-deadline" placeholder="optional"></div>
            </div>
          </div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Dispatch Options</h3><button class="action-btn" data-action="dispatch-usage-continuations">Dispatch Ready</button></div>
            <div class="form-grid">
              <div class="field span-6"><label for="usage-dispatched-by">Dispatched By</label><input id="usage-dispatched-by" value="quark"></div>
              <div class="field span-6 check-field"><label><input id="usage-resume-codex-projects" type="checkbox"> Resume Codex Projects</label></div>
            </div>
          </div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Tank/MSI Remote Testing</h3><div class="actions"><button class="action-btn" data-action="record-remote-testing-profile">Save Profile</button><button class="action-btn" data-action="request-remote-testing-lease">Request Lease</button><button class="action-btn" data-action="enqueue-remote-test-job">Queue Job</button><button class="action-btn" data-action="collect-remote-test-results">Collect Results</button></div></div>
            <div class="form-grid">
              <div class="field span-4"><label for="remote-profile-id">Profile ID</label><input id="remote-profile-id" value="${safe(remoteTesting.default_profile_id || "remote-testing.tank-msi")}"></div>
              <div class="field span-4"><label for="remote-display-name">Display Name</label><input id="remote-display-name" value="Tank on MSI remote testing queue"></div>
              <div class="field span-4"><label for="remote-worker-hint">Worker</label><input id="remote-worker-hint" value="overseer-msi-test-agent"></div>
              <div class="field span-3"><label for="remote-recorded-by">Recorded By</label><input id="remote-recorded-by" value="quark"></div>
              <div class="field span-3"><label for="remote-base-url">Base URL</label><input id="remote-base-url" value="http://127.0.0.1:8766"></div>
              <div class="field span-3"><label for="remote-ui-path">UI Path</label><input id="remote-ui-path" value="/Overseer/ui"></div>
              <div class="field span-3"><label for="remote-gateway-path">Gateway Path</label><input id="remote-gateway-path" value="/Overseer"></div>
              <div class="field span-3"><label for="remote-token-source">Token Source</label><input id="remote-token-source" value="state/api-token"></div>
              <div class="field span-3"><label for="remote-host">Remote Host</label><input id="remote-host" value="god@10.50.0.100"></div>
              <div class="field span-3"><label for="remote-lease-id">Lease ID</label><input id="remote-lease-id" value="lease.overseer.tank-regression"></div>
              <div class="field span-3"><label for="remote-project">Project</label><input id="remote-project" value="Overseer"></div>
              <div class="field span-3"><label for="remote-requested-by">Requested By</label><input id="remote-requested-by" value="quark"></div>
              <div class="field span-3"><label for="remote-ttl-minutes">TTL Minutes</label><input id="remote-ttl-minutes" type="number" min="1" value="120"></div>
              <div class="field span-9"><label for="remote-purpose">Purpose</label><input id="remote-purpose" value="run protected-gateway regression without human relay"></div>
              <div class="field span-3"><label for="remote-priority">Priority</label><input id="remote-priority" value="normal"></div>
              <div class="field span-6"><label for="remote-job-types">Allowed Job Types</label><input id="remote-job-types" value="ping,overseer.auth_panel_smoke,overseer.full_ui_regression,overseer.performance_regression"></div>
              <div class="field span-3"><label for="remote-job-lease-id">Job Lease</label><input id="remote-job-lease-id" value="lease.overseer.tank-regression"></div>
              <div class="field span-3"><label for="remote-job-type">Job Type</label><input id="remote-job-type" value="ping"></div>
              <div class="field span-8"><label for="remote-job-params">Job Params</label><textarea id="remote-job-params">{}</textarea></div>
              <div class="field span-2"><label for="remote-result-lease-id">Result Lease</label><input id="remote-result-lease-id" value="lease.overseer.tank-regression"></div>
              <div class="field span-2"><label for="remote-result-job-id">Result Job</label><input id="remote-result-job-id" placeholder="optional"></div>
            </div>
          </div>
          <div class="panel span-12">${table("Usage Limits", usage.items || [], ["limit_id", "resource_id", "remaining", "capacity", "resets_at"], {fills: {limit_id: (row) => usageLimitFill(row), resource_id: (row) => usageLimitFill(row)}, fillView: "usage"})}</div>
          <div class="panel span-12">${table("Quota Evidence", usageEvidence.limit_evidence || [], ["limit_id", "resource_id", "remaining", "capacity", "usage_percent", "status", "next_step"], {fills: {limit_id: (row) => usageLimitFill(row)}, fillView: "usage"})}</div>
          <div class="panel span-12">${table("Exhaustion Forecast", usageEvidence.exhaustion_forecast || [], ["limit_id", "remaining", "queued_units", "remaining_after_queue", "deficit_units", "status", "next_step"], {fills: {limit_id: (row) => usageLimitFill(row)}, fillView: "usage"})}</div>
          <div class="panel span-6">${table("Continuation Queue Evidence", usageEvidence.continuation_queue || [], ["request_id", "limit_id", "owner_thread", "requested_units", "status"], {fills: {limit_id: (row) => usageLimitFill(row)}, fillView: "usage"})}</div>
          <div class="panel span-6">${table("Usage Allocation By Thread", usageEvidence.allocation_by_thread || [], ["owner_thread", "requests", "requested_units", "status"])}</div>
          <div class="panel span-6">${table("Remote Testing Profiles", remoteTesting.connection_profiles || [], ["profile_id", "remote_operator", "remote_host", "protected_gateway_required", "forbidden_transports", "worker_hint"])}</div>
          <div class="panel span-6">${table("Remote Testing Leases", remoteTesting.leases || [], ["lease_id", "project", "status", "expires_at"])}</div>
          <div class="panel span-6">${table("Remote Pending Jobs", remoteTesting.pending_jobs || [], ["job_id", "job_type", "lease_id", "status"], {limit: 20})}</div>
          <div class="panel span-6">${table("Remote Test Results", remoteTesting.recent_results || [], ["job_id", "job_type", "status", "stage"], {limit: 20})}</div>
          <div class="panel span-12">${table("Cost And Forecast Coverage", operations.usage_costs || [], ["limit_id", "remaining", "capacity", "queued_requests", "queued_units", "deficit_units", "cost_tracking", "forecast"], {fills: {limit_id: (row) => usageLimitFill(row)}, fillView: "usage"})}</div>
          ${officerPanel("quark", "MCP API quota scheduling", "Track API-keyed MCP call limits and schedule continuation after the quota window resets.", "limit.mcp.api.calls.daily")}
        </div>`;
    }
    function renderEzri() {
      const status = state.data.documentsStatus || {};
      const git = state.data.gitStatus || {};
      const gitAccount = git.account || {};
      const notes = state.data.documentsNotes || {};
      const capture = state.data.knowledgeCapturePlan || {};
      const documentationEvidence = state.data.documentationEvidence || {};
      const currentFolder = notes.folder || state.documentsFolder || "Overseer";
      state.documentsFolder = currentFolder;
      const files = (notes.files || []).map((file) => ({
        file,
        kind: String(file).endsWith("/") ? "folder" : "note",
        path: documentChildPath(currentFolder, file)
      }));
      const repos = gitAccount.repositories || [];
      const captureItems = capture.items || [];
      const captureTone = capture.failed ? "bad" : capture.candidate_count ? "pending" : "good";
      const gitTone = git.conflicted ? "bad" : git.dirty ? "warn" : "good";
      const gitRemote = git.remote || {};
      const gitLinks = git.links || {};
      const linkRows = [
        {label: "Repository", url: gitLinks.repository},
        {label: "Branch", url: gitLinks.branch},
        {label: "Commit", url: gitLinks.commit},
        {label: "Pull Requests", url: gitLinks.pulls},
        {label: "Actions", url: gitLinks.actions}
      ].filter((row) => row.url);
      const workflows = ezriWorkflowRows();
      const operations = state.data.operations || {};
      document.getElementById("ezri").innerHTML = `
        <div class="grid">
          ${stationIntro("Ezri", "Knowledge Base", "Operational notes, git state, event capture, runbooks, and vault search.", ["documents", "git", "runbooks"])}
          ${metric("REST API", status.available ? "online" : "offline", "Obsidian Local REST", "span-3", status.available ? "good" : "bad", "ezri")}
          ${metric("Auth", status.authenticated ? "valid" : "blocked", "stored bearer token", "span-3", status.authenticated ? "good" : "warn", "ezri")}
          ${metric("Vault Notes", notes.count, notes.folder || "Overseer", "span-3", "", "ezri")}
          ${metric("Capture Queue", capture.candidate_count, "crew and audit events", "span-3", captureTone, "ezri")}
          ${metric("Repositories", gitAccount.repository_count ?? 0, gitAccount.root || "workspace", "span-3", repos.length ? "good" : "inactive", "ezri")}
          ${metric("Dirty Repos", gitAccount.dirty_count ?? 0, "account working trees", "span-3", gitAccount.dirty_count ? "warn" : "good", "ezri")}
          ${metric("Remote Repos", gitAccount.with_remote_count ?? 0, "linked to Git remotes", "span-3", gitAccount.with_remote_count ? "good" : "inactive", "ezri")}
          ${metric("Current Repo", gitRemote.repo || git.branch || "none", gitRemote.owner || "local only", "span-3", gitRemote.web_url ? "good" : gitTone, "ezri")}
          <div class="panel span-6">${kv("Documents Runtime", {
            service: status.service || "unavailable",
            status: status.available ? "online" : "offline",
            authenticated: status.authenticated ? "yes" : "no",
            obsidian: status.versions?.obsidian,
            plugin: status.manifest?.version,
            writes: (status.allowed_write_prefixes || []).join(", ")
          })}</div>
          <div class="panel span-6">${kv("Git Runtime", {
            repository: git.repo_path,
            account_root: gitAccount.root,
            branch: git.branch,
            head: git.short_head,
            upstream: git.upstream,
            dirty: git.dirty ? "yes" : "no",
            conflicted: git.conflicted || 0,
            remote: gitRemote.web_url
          })}</div>
          <div class="panel span-12">${table("Account Repositories", repos, ["relative_path", "branch", "dirty", "changed", "remote_owner", "remote_repo"], {external: {remote_repo: (row) => row.remote_url}, fills: {relative_path: (row) => ({ "documents-query": row.relative_path || row.name || "" })}, fillView: "ezri"})}</div>
          <div class="panel span-6">${table("Current Repo Links", linkRows, ["label", "url"], {external: {url: true}})}</div>
          <div class="panel span-6">${table("Current Working Tree", git.status_lines || [], ["status", "path"])}</div>
          <div class="panel span-12 workflow-panel">${table("Workflows", workflows, ["workflow", "page", "owner", "action", "source"], {limit: 80, fills: {workflow: (row) => workflowFill(row), source: (row) => workflowFill(row)}, fillView: "ezri"})}</div>
          <div class="panel span-6">${table("Documentation Coverage", [operations.documentation || {}], ["docs_count", "expected_runbooks", "present_runbooks", "missing_runbooks", "next_step"])}</div>
          <div class="panel span-6">${table("Runbook Coverage", documentationEvidence.runbook_coverage || [], ["runbook", "present", "status"], {fills: {runbook: (row) => ({ "documents-note-path": row.path || "", "documents-query": row.runbook || "" })}, fillView: "ezri"})}</div>
          <div class="panel span-6">${table("Workflow Coverage", documentationEvidence.workflow_coverage || [], ["workflow", "source", "status"], {limit: 40, fills: {workflow: (row) => ({ "documents-query": row.workflow || "", "documents-note-path": row.source || "" })}, fillView: "ezri"})}</div>
          <div class="panel span-6">${table("Stale Document Candidates", documentationEvidence.stale_documents || [], ["path", "age_days", "status"], {fills: {path: (row) => ({ "documents-note-path": row.path || "", "documents-query": row.path || "" })}, fillView: "ezri"})}</div>
          <div class="panel span-6">${table("ADR Index", documentationEvidence.adr_index || [], ["path", "status"], {fills: {path: (row) => ({ "documents-note-path": row.path || "" })}, fillView: "ezri"})}</div>
          <div class="panel span-6">${table("Release Index", documentationEvidence.release_index || [], ["path", "status"], {fills: {path: (row) => ({ "documents-note-path": row.path || "" })}, fillView: "ezri"})}</div>
          <div class="panel span-6">${table("Current Folder", files, ["kind", "file"], {fills: {file: (row) => documentFileFill(row)}, fillActions: {file: (row) => row.kind === "folder" ? "documents-list-notes" : ""}, fillView: "ezri"})}</div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Search and List</h3><div class="actions"><button class="action-btn" data-action="documents-search">Search</button><button class="action-btn" data-action="documents-list-notes">List Folder</button></div></div>
            <div class="form-grid">
              <div class="field span-6"><label for="documents-query">Query</label><input id="documents-query" value="${safe(state.documentsQuery || "Overseer")}"></div>
              <div class="field span-3"><label for="documents-context-length">Context</label><input id="documents-context-length" type="number" min="0" value="100"></div>
              <div class="field span-3"><label for="documents-folder">Folder</label><input id="documents-folder" value="${safe(currentFolder)}"></div>
            </div>
          </div>
          <div class="panel span-6">
            <div class="toolbar"><h3>Write Note</h3><button class="action-btn" data-action="documents-write-note">Save</button></div>
            <div class="form-grid">
              <div class="field span-6"><label for="documents-note-path">Path</label><input id="documents-note-path" value="Overseer/Inbox/operator-note.md"></div>
              <div class="field span-3"><label for="documents-note-mode">Mode</label><select id="documents-note-mode"><option value="append">append</option><option value="replace">replace</option></select></div>
              <div class="field span-6"><label for="documents-note-content">Content</label><textarea id="documents-note-content">## Operator note&#10;&#10;</textarea></div>
            </div>
          </div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Knowledge Capture</h3><div class="actions"><span class="pill pending">${safe(capture.candidate_count ?? 0)} queued</span><button class="action-btn" data-action="documents-capture-knowledge">Capture</button></div></div>
            <div class="form-grid">
              <div class="field span-3"><label for="knowledge-capture-limit">Limit</label><input id="knowledge-capture-limit" type="number" min="1" value="${safe(capture.limit || 12)}"></div>
            </div>
            ${table("Capture Candidates", captureItems, ["kind", "source_id", "owner_domain", "path"], {links: {owner_domain: (row) => domainView(row.owner_domain)}, fills: {path: (row) => ({ "documents-note-path": row.path || "" })}, fillView: "ezri"})}
          </div>
          ${officerPanel("ezri", "Documentation support", "Capture, find, summarize, or update Overseer docs, runbooks, decisions, and troubleshooting notes.")}
        </div>`;
    }
    function ezriWorkflowRows() {
      const source = "Overseer/Runbooks/operator-workflows.md";
      return [
        {workflow: "Review command status", page: "Driver", owner: "Sisko", action: "discover-agent-sessions", source, query: "Review command status"},
        {workflow: "Review command status", page: "Driver", owner: "Sisko", action: "resume-agent-sessions", source, query: "Review command status"},
        {workflow: "Review command status", page: "Driver", owner: "Sisko", action: "checkpoint-agent", source, query: "Review command status"},
        {workflow: "Review command status", page: "Driver", owner: "Sisko", action: "handoff-agent", source, query: "Review command status"},
        {workflow: "Review command status", page: "Driver", owner: "Sisko", action: "failover-agent", source, query: "Review command status"},
        {workflow: "Review command status", page: "Driver", owner: "Sisko", action: "recover-agent-failover", source, query: "Review command status"},
        {workflow: "Review command status", page: "Overview", owner: "Sisko", action: "open drilldown", source, query: "Review command status"},
        {workflow: "Record an operations workflow", page: "Overview", owner: "Sisko / Ezri", action: "record-operation", source, query: "Record an operations workflow"},
        {workflow: "Stage a gap workflow from a template", page: "Overview", owner: "Sisko / Ezri", action: "stage-operation-workflow", source, query: "Stage a gap workflow from a template"},
        {workflow: "Transition an operations record", page: "Overview", owner: "Sisko", action: "transition-operation", source, query: "Transition an operations record"},
        {workflow: "Dispatch open crew requests", page: "Overview", owner: "Sisko", action: "dispatch-crew-messages", source, query: "Dispatch open crew requests"},
        {workflow: "Send a crew request", page: "Any", owner: "Sisko", action: "send-crew-message", source, query: "Send a crew request"},
        {workflow: "Approve a pending admin request", page: "Admin", owner: "Sisko", action: "approve-admin-change", source, query: "Approve a pending admin request"},
        {workflow: "Approve and implement an admin request", page: "Admin", owner: "Sisko / O'Brien", action: "approve-and-execute-admin-change", source, query: "Approve and implement an admin request"},
        {workflow: "Request changes for a plan", page: "Admin", owner: "Sisko", action: "cancel-admin-change", source, query: "Request changes for a plan"},
        {workflow: "Plan a service restart or admin change", page: "Admin", owner: "O'Brien", action: "plan-admin-change", source, query: "Plan a service restart or admin change"},
        {workflow: "Execute an approved admin plan", page: "Admin", owner: "O'Brien", action: "execute-admin-change", source, query: "Execute an approved admin plan"},
        {workflow: "Plan package updates", page: "Admin", owner: "O'Brien", action: "plan-package-updates", source, query: "Plan package updates"},
        {workflow: "Plan firmware updates", page: "Admin", owner: "O'Brien / Sisko", action: "plan-firmware-updates", source, query: "Plan firmware updates"},
        {workflow: "Run package maintenance cycle", page: "Admin", owner: "O'Brien", action: "run-package-maintenance-cycle", source, query: "Run package maintenance cycle"},
        {workflow: "Refresh CVE advisory feeds", page: "Admin", owner: "O'Brien", action: "refresh-advisories", source, query: "Refresh CVE advisory feeds"},
        {workflow: "Discover user services", page: "Admin", owner: "O'Brien / Julian", action: "discover-user-services", source, query: "Discover user services"},
        {workflow: "Enable a live adapter", page: "Admin", owner: "Sisko / O'Brien", action: "request-admin-adapter-enablement", source, query: "Enable a live adapter"},
        {workflow: "Approve adapter enablement", page: "Admin", owner: "Sisko", action: "approve-admin-adapter-enablement", source, query: "Approve adapter enablement"},
        {workflow: "Archive inactive admin history", page: "Admin", owner: "Sisko", action: "request-admin-archive", source, query: "Archive inactive admin history"},
        {workflow: "Approve admin history archive", page: "Admin", owner: "Sisko", action: "approve-admin-archive", source, query: "Approve admin history archive"},
        {workflow: "Run approved admin archive", page: "Admin", owner: "Sisko", action: "archive-admin-history", source, query: "Run approved admin archive"},
        {workflow: "Restore archived admin history", page: "Admin", owner: "Sisko", action: "request-admin-restore", source, query: "Restore archived admin history"},
        {workflow: "Approve admin history restore", page: "Admin", owner: "Sisko", action: "approve-admin-restore", source, query: "Approve admin history restore"},
        {workflow: "Unarchive an approved admin plan", page: "Admin", owner: "Sisko", action: "unarchive-admin-history", source, query: "Unarchive an approved admin plan"},
        {workflow: "Customize policy defaults", page: "Admin", owner: "Sisko", action: "build-policy-profile", source, query: "Customize policy defaults"},
        {workflow: "Accept a policy warning", page: "Admin", owner: "Sisko", action: "request-policy-warning", source, query: "Accept a policy warning"},
        {workflow: "Approve a policy warning", page: "Admin", owner: "Sisko", action: "approve-policy-warning", source, query: "Approve a policy warning"},
        {workflow: "Discover physical devices", page: "Assets", owner: "Kira", action: "discover-physical", source, query: "Discover physical devices"},
        {workflow: "Discover storage arrays", page: "Assets", owner: "Kira", action: "discover-storage", source, query: "Discover storage arrays"},
        {workflow: "Discover listeners as virtual assets", page: "Assets", owner: "Dax", action: "discover-listeners", source, query: "Discover listeners as virtual assets"},
        {workflow: "Register a managed resource", page: "Assets", owner: "Kira / Dax", action: "register-resource", source, query: "Register a managed resource"},
        {workflow: "Capture filesystem growth snapshot", page: "Assets", owner: "Kira", action: "capture-storage-growth-snapshot", source, query: "Capture filesystem growth snapshot"},
        {workflow: "Review storage risk alerts", page: "Assets", owner: "Kira", action: "open Assets", source, query: "Review storage risk alerts"},
        {workflow: "Review storage encryption and removable media trust", page: "Assets", owner: "Kira", action: "open Assets", source, query: "Review storage encryption and removable media trust"},
        {workflow: "Record a backup job", page: "Assets", owner: "Kira", action: "record-backup-job", source, query: "Record a backup job"},
        {workflow: "Review backup provider readiness", page: "Assets", owner: "Kira", action: "open Assets", source, query: "Review Backup Provider Readiness"},
        {workflow: "Record a restore test", page: "Assets", owner: "Kira", action: "record-restore-test", source, query: "Record a restore test"},
        {workflow: "Stage backup execution request", page: "Assets", owner: "Kira", action: "stage-backup-execution-request", source, query: "Stage backup execution request"},
        {workflow: "Approve backup execution request", page: "Assets", owner: "Sisko / Kira", action: "approve-backup-execution-request", source, query: "Approve backup execution request"},
        {workflow: "Execute backup execution request", page: "Assets", owner: "Kira", action: "execute-backup-execution-request", source, query: "Execute backup execution request"},
        {workflow: "Stage restore execution request", page: "Assets", owner: "Kira", action: "stage-restore-execution-request", source, query: "Stage restore execution request"},
        {workflow: "Approve restore execution request", page: "Assets", owner: "Sisko / Kira", action: "approve-restore-execution-request", source, query: "Approve restore execution request"},
        {workflow: "Execute restore execution request", page: "Assets", owner: "Kira", action: "execute-restore-execution-request", source, query: "Execute restore execution request"},
        {workflow: "Stage backup cleanup request", page: "Assets", owner: "Kira", action: "stage-backup-cleanup-request", source, query: "Stage backup cleanup request"},
        {workflow: "Approve backup cleanup request", page: "Assets", owner: "Kira", action: "approve-backup-cleanup-request", source, query: "Approve backup cleanup request"},
        {workflow: "Execute backup cleanup request", page: "Assets", owner: "Kira", action: "execute-backup-cleanup-request", source, query: "Execute backup cleanup request"},
        {workflow: "View VM leases and virtual claims", page: "Claims", owner: "Dax", action: "open Claims", source, query: "View VM leases and virtual claims"},
        {workflow: "Record virtual runtime state", page: "Claims", owner: "Dax", action: "record-virtual-runtime", source, query: "Record virtual runtime state"},
        {workflow: "Stage real provider target setup batch", page: "Claims", owner: "Dax", action: "stage-virtual-target-setup-batch", source, query: "Stage real provider target setup batch"},
        {workflow: "Execute approved provider target setup", page: "Claims", owner: "Dax", action: "execute-virtual-target-setup", source, query: "Execute approved provider target setup"},
        {workflow: "Record real provider setup result", page: "Claims", owner: "Dax", action: "record-virtual-target-setup-result", source, query: "Record real provider setup result"},
        {workflow: "Execute virtual lifecycle action", page: "Claims", owner: "Dax", action: "execute-virtual-lifecycle", source, query: "Execute virtual lifecycle action"},
        {workflow: "Stage virtual snapshot request", page: "Claims", owner: "Dax", action: "stage-virtual-snapshot-request", source, query: "Stage virtual snapshot request"},
        {workflow: "Approve virtual snapshot request", page: "Claims", owner: "Sisko / Dax", action: "approve-virtual-snapshot-request", source, query: "Approve virtual snapshot request"},
        {workflow: "Execute virtual snapshot request", page: "Claims", owner: "Dax", action: "execute-virtual-snapshot-request", source, query: "Execute virtual snapshot request"},
        {workflow: "Stage virtual restore request", page: "Claims", owner: "Dax", action: "stage-virtual-restore-request", source, query: "Stage virtual restore request"},
        {workflow: "Approve virtual restore request", page: "Claims", owner: "Sisko / Dax", action: "approve-virtual-restore-request", source, query: "Approve virtual restore request"},
        {workflow: "Execute virtual restore request", page: "Claims", owner: "Dax", action: "execute-virtual-restore-request", source, query: "Execute virtual restore request"},
        {workflow: "Stage virtual destroy request", page: "Claims", owner: "Dax", action: "stage-virtual-destroy-request", source, query: "Stage virtual destroy request"},
        {workflow: "Approve virtual destroy request", page: "Claims", owner: "Sisko / Dax", action: "approve-virtual-destroy-request", source, query: "Approve virtual destroy request"},
        {workflow: "Execute virtual destroy request", page: "Claims", owner: "Dax", action: "execute-virtual-destroy-request", source, query: "Execute virtual destroy request"},
        {workflow: "Stage image vulnerability scan", page: "Claims", owner: "Dax", action: "stage-image-scan", source, query: "Stage image vulnerability scan"},
        {workflow: "Approve image vulnerability scan", page: "Claims", owner: "Sisko / Dax", action: "approve-image-scan", source, query: "Approve image vulnerability scan"},
        {workflow: "Execute image vulnerability scan", page: "Claims", owner: "Dax", action: "execute-image-scan", source, query: "Execute image vulnerability scan"},
        {workflow: "Request a VM, port, gateway, or device claim", page: "Claims", owner: "Dax", action: "request-claim", source, query: "Request a VM port gateway or device claim"},
        {workflow: "Approve a resource claim", page: "Claims", owner: "Sisko / Dax", action: "approve-claim", source, query: "Approve a resource claim"},
        {workflow: "Activate an approved claim", page: "Claims", owner: "Dax", action: "activate-claim", source, query: "Activate an approved claim"},
        {workflow: "Release a claim", page: "Claims", owner: "Dax", action: "release-claim", source, query: "Release a claim"},
        {workflow: "Clean up stale or expired claims", page: "Claims", owner: "Dax", action: "request-claim-cleanup", source, query: "Clean up stale or expired claims"},
        {workflow: "Approve claim cleanup", page: "Claims", owner: "Sisko / Dax", action: "approve-claim-cleanup", source, query: "Approve claim cleanup"},
        {workflow: "Execute approved claim cleanup", page: "Claims", owner: "Dax", action: "execute-claim-cleanup", source, query: "Execute approved claim cleanup"},
        {workflow: "Inspect host security posture", page: "Security", owner: "Odo", action: "inspect-host", source, query: "Inspect host security posture"},
        {workflow: "Advance Odo security review to approval or execution", page: "Security", owner: "Odo", action: "advance-odo-security", source, query: "Advance Odo security review to approval or execution"},
        {workflow: "Stage listener remediation plans", page: "Security", owner: "Odo", action: "plan-listener-queue-remediations", source, query: "Stage listener remediation plans"},
        {workflow: "Plan one listener remediation", page: "Security", owner: "Odo", action: "plan-host-security-remediation", source, query: "Plan one listener remediation"},
        {workflow: "Review a remote source", page: "Security", owner: "Odo", action: "record-source-review", source, query: "Review a remote source"},
        {workflow: "Plan a source block", page: "Security", owner: "Odo", action: "plan-source-block", source, query: "Plan a source block"},
        {workflow: "Stage firewall policy enforcement", page: "Security", owner: "Odo Firewall", action: "stage-firewall-policy-enforcement", source, query: "Stage firewall policy enforcement"},
        {workflow: "Execute approved firewall change", page: "Security", owner: "Odo Firewall", action: "execute-firewall-change", source, query: "Execute approved firewall change"},
        {workflow: "Stage identity rotation request", page: "Security", owner: "Odo", action: "stage-identity-rotation-request", source, query: "Stage identity rotation request"},
        {workflow: "Approve identity rotation request", page: "Security", owner: "Sisko / Odo", action: "approve-identity-rotation-request", source, query: "Approve identity rotation request"},
        {workflow: "Execute identity rotation request", page: "Security", owner: "Odo", action: "execute-identity-rotation-request", source, query: "Execute identity rotation request"},
        {workflow: "Review key broker providers and token grants", page: "Security", owner: "Odo / Quark", action: "view-key-broker-status", source: `${source}#key-broker`, query: "Review key broker providers and token grants"},
        {workflow: "Prepare an IDS review package", page: "Security", owner: "Odo IDS", action: "prepare-ids-review-package", source, query: "Prepare an IDS review package"},
        {workflow: "Export an IDS review prompt", page: "Security", owner: "Odo IDS", action: "export-ids-review-prompt", source, query: "Export an IDS review prompt"},
        {workflow: "Dispatch an IDS review package", page: "Security", owner: "Odo IDS", action: "dispatch-ids-review-package", source, query: "Dispatch an IDS review package"},
        {workflow: "Record an IDS review result", page: "Security", owner: "Odo IDS", action: "record-ids-review-result", source, query: "Record an IDS review result"},
        {workflow: "View logs from an unhealthy service", page: "Health", owner: "Julian", action: "run-health-probes", source, query: "View logs from an unhealthy service"},
        {workflow: "Stage system journal access request", page: "Health", owner: "Julian", action: "stage-journal-access-request", source, query: "Stage system journal access request"},
        {workflow: "Execute approved system journal capture", page: "Health", owner: "Julian", action: "execute-journal-access-request", source, query: "Execute approved system journal capture"},
        {workflow: "Capture metric history snapshot", page: "Health", owner: "Julian", action: "capture-metric-history", source, query: "Capture metric history snapshot"},
        {workflow: "Run health probes", page: "Health", owner: "Julian", action: "run-health-probes", source, query: "Run health probes"},
        {workflow: "Register a health target", page: "Health", owner: "Julian", action: "register-health-target", source, query: "Register a health target"},
        {workflow: "Check an exhausted limit refresh", page: "Usage", owner: "Quark", action: "open Usage", source, query: "Check an exhausted limit refresh"},
        {workflow: "Record a usage limit", page: "Usage", owner: "Quark", action: "record-usage-limit", source, query: "Record a usage limit"},
        {workflow: "Request continuation after quota refresh", page: "Usage", owner: "Quark", action: "request-usage-continuation", source, query: "Request continuation after quota refresh"},
        {workflow: "Dispatch ready continuation work", page: "Usage", owner: "Quark", action: "dispatch-usage-continuations", source, query: "Dispatch ready continuation work"},
        {workflow: "Discover Codex project threads", page: "Usage", owner: "Quark", action: "discover-codex-threads", source, query: "Discover Codex project threads"},
        {workflow: "Save Tank/MSI remote testing profile", page: "Usage", owner: "Quark", action: "record-remote-testing-profile", source, query: "Save Tank MSI remote testing profile"},
        {workflow: "Manage Tank/MSI remote testing", page: "Usage", owner: "Quark", action: "request-remote-testing-lease", source, query: "Manage Tank MSI remote testing"},
        {workflow: "Queue a Tank/MSI remote test job", page: "Usage", owner: "Quark", action: "enqueue-remote-test-job", source, query: "Queue a Tank MSI remote test job"},
        {workflow: "Run mobile UI emulator regression", page: "Usage", owner: "Quark", action: "request-remote-testing-lease", source, query: "Run Mobile UI Emulator Regression"},
        {workflow: "Collect Tank/MSI remote test results", page: "Usage", owner: "Quark", action: "collect-remote-test-results", source, query: "Collect Tank MSI remote test results"},
        {workflow: "Search documentation", page: "Documents", owner: "Ezri", action: "documents-search", source, query: "Search documentation"},
        {workflow: "List a documentation folder", page: "Documents", owner: "Ezri", action: "documents-list-notes", source, query: "List a documentation folder"},
        {workflow: "Write an approved note", page: "Documents", owner: "Ezri", action: "documents-write-note", source, query: "Write an approved note"},
        {workflow: "Capture crew and audit knowledge", page: "Documents", owner: "Ezri", action: "documents-capture-knowledge", source, query: "Capture crew and audit knowledge"},
        {workflow: "View git account status", page: "Documents", owner: "Ezri", action: "open Documents", source, query: "View git account status"},
        {workflow: "View audit log", page: "Audit", owner: "Sisko", action: "open Audit", source, query: "View audit log"},
        {workflow: "Review approval history", page: "Audit", owner: "Sisko", action: "open Audit", source, query: "Review approval history"},
        {workflow: "Adjust service schedule", page: "Admin", owner: "O'Brien", action: "record-maintenance-schedule", source, query: "Adjust service schedule"}
      ];
    }
    function renderAudit() {
      const audit = state.data.audit || {};
      const approvals = state.data.approvals || {};
      document.getElementById("audit").innerHTML = `
        <div class="grid">
          ${stationIntro("Sisko", "Audit Log", "Decision history, approvals, and operational evidence.", ["approvals", "events", "policy evidence"])}
          ${metric("Audit Events", audit.event_count, "stored", "span-3", "", "audit")}
          ${metric("Approvals", approvals.approval_count, "stored", "span-3", approvals.pending_count ? "warn" : "good", "admin")}
          <div class="panel span-6">${table("Recent Audit", audit.events || [], ["id", "event_type", "owner_domain", "summary"], {links: {owner_domain: (row) => domainView(row.owner_domain)}})}</div>
          <div class="panel span-6">${table("Approvals", approvals.approvals || approvals.items || [], ["id", "status", "owner_domain", "reason"], {links: {owner_domain: (row) => domainView(row.owner_domain)}, fills: {id: (row) => approvalFill(row)}, fillView: "admin"})}</div>
          ${officerPanel("sisko", "Audit review", "Review decision history, approvals, evidence, or policy concerns.")}
        </div>`;
    }
    function stationIntro(officer, titleText, summary, chips) {
      const chipMarkup = (chips || []).map((chip) => `<span class="station-chip">${safe(chip)}</span>`).join("");
      return `<div class="station-intro">
        <div>
          <h2>${safe(titleText)}</h2>
          <p>${safe(summary)}</p>
          <div class="station-strip">${chipMarkup}</div>
        </div>
        <div class="station-code"><span>${safe(officer)}</span><span>${safe(crewStation(officer))}</span></div>
      </div>`;
    }
    function authorizationDecisionBoard(auth, readiness) {
      const pendingPlans = auth.pending || [];
      const approvalGroups = [
        ...(auth.adapter_enablement_approvals || []),
        ...(auth.archive_approvals || []),
        ...(auth.restore_approvals || []),
        ...(auth.policy_warning_approvals || []),
        ...(auth.claim_cleanup_approvals || []),
        ...(auth.daemon_migration_approvals || [])
      ];
      const readinessById = Object.fromEntries((readiness.items || []).map((item) => [item.id, item]));
      const cards = [
        ...pendingPlans.map((plan) => adminPlanDecisionCard(plan, readinessById[plan.id] || {})),
        ...approvalGroups.map((approval) => approvalDecisionCard(approval))
      ].join("");
      return `<div class="panel span-12 decision-card">
        <div class="toolbar"><h3>Approval Decisions</h3><span class="pill ${auth.pending_count ? "warn" : "good"}">${safe(auth.pending_count || 0)} pending</span></div>
        <div class="grid">${cards || "<p class='muted'>No pending approval decisions.</p>"}</div>
      </div>`;
    }
    function adminPlanDecisionCard(plan, readiness) {
      const planId = plan.id || readiness.id || "";
      const fields = adminPlanFill(planId);
      const requestChange = {
        ...fields,
        "admin-cancel-reason": `changes requested before approval: ${plan.next_step || readiness.next_step || plan.reason || ""}`
      };
      const reviewId = `review-${slug(planId || plan.kind || "admin-plan")}`;
      const brief = plan.review_brief || {};
      return `<div class="panel span-6 decision-card ${normalizeTone(stateTone(plan.risk_level))}">
        <div class="toolbar"><h3>${safe(plan.kind || "Admin Plan")}</h3><span class="pill ${stateTone(plan.risk_level)}">${safe(plan.approval_level || "approval")}</span></div>
        ${decisionContext("Decision Context", {
          plan_id: planId,
          owner: plan.owner_domain,
          target: plan.target,
          risk: plan.risk_level,
          reason: plan.reason,
          readiness: readiness.readiness_state,
          ids_review: plan.ids_review_gate_satisfied ? "satisfied" : "required",
          next_step: plan.next_step || readiness.next_step
        }, reviewId)}
        ${reviewBriefMarkup(reviewId, brief)}
        <div class="actions">
          ${fillButton("Review Source", fields, "admin")}
          ${plan.ids_review_gate_satisfied === false ? `<button type="button" class="action-btn" disabled>Waiting On IDS</button>` : `<button type="button" class="action-btn" data-fill="${safe(JSON.stringify(fields))}" data-view-target="admin" data-action="approve-and-execute-admin-change">Approve & Implement</button>`}
          ${fillButton("Request Changes", requestChange, "admin", "cancel-admin-change")}
        </div>
      </div>`;
    }
    function decisionContext(titleText, value, reviewId) {
      const rows = Object.entries(value || {}).slice(0, 12).map(([key, val]) => {
        const body = key === "plan_id" && val
          ? `<a class="cell-link" href="#${safe(reviewId)}">${format(val)}</a>`
          : format(val);
        return `<div class="row"><span>${safe(labelize(key))}</span><strong>${body}</strong></div>`;
      }).join("");
      return `<h3>${safe(titleText)}</h3><div class="list">${rows || "<p class='muted'>No data</p>"}</div>`;
    }
    function reviewBriefMarkup(reviewId, brief) {
      const items = {
        change: brief.change,
        remediation: brief.remediation,
        reasoning: brief.reasoning,
        approve_effect: brief.approve_effect,
        deny_effect: brief.deny_effect,
        service_impact: brief.service_impact,
        alternatives: brief.alternatives,
        commands: brief.commands,
        rollback: brief.rollback,
        verification: brief.verification,
        risks: brief.risks
      };
      const rows = Object.entries(items)
        .filter(([, val]) => val !== undefined && val !== null && String(Array.isArray(val) ? val.join(", ") : val).trim())
        .map(([key, val]) => `<div class="row"><span>${safe(labelize(key))}</span><strong>${format(val)}</strong></div>`)
        .join("");
      return `<details id="${safe(reviewId)}"><summary>Plain-English Review</summary><div class="review-brief">${rows || "<p class='muted'>No review brief available.</p>"}</div></details>`;
    }
    function approvalDecisionCard(approval) {
      const fields = approvalFill(approval);
      const approveAction = approvalAction(approval);
      const changeFields = crewDecisionFill("sisko", "Administrative decision", {
        subject: `Request changes for ${approval.id || approval.subject_id || "approval"}`,
        message: `${approval.reason || "Approval needs revision."}\n\nEvidence required: ${(approval.evidence_required || []).join(", ")}`
      });
      const siskoDecisionPrefix = rolePrefix("sisko-Administrative decision");
      return `<div class="panel span-6 decision-card ${stateTone(approval.status)}">
        <div class="toolbar"><h3>${safe(approval.owner_domain || "Approval")}</h3><span class="pill ${stateTone(approval.status)}">${safe(approval.status || "pending")}</span></div>
        ${kv("Approval Context", {
          approval_id: approval.id,
          subject: approval.subject_id,
          level: approval.approval_level,
          requester: approval.requester_thread,
          reason: approval.reason,
          evidence: (approval.evidence_required || []).join(", "),
          next_step: approval.next_step
        })}
        <div class="actions">
          ${fillButton("Review Source", fields, "admin")}
          ${approveAction ? fillButton("Approve", fields, "admin", approveAction) : fillButton("Load Approval", fields, "admin")}
          ${fillButton("Request Changes", changeFields, "admin", "send-crew-message", {"data-role": "sisko", "data-prefix": siskoDecisionPrefix})}
        </div>
      </div>`;
    }
    function fillButton(label, fields, view = "", action = "", attrs = {}) {
      const extra = Object.entries(attrs).map(([key, value]) => ` ${safe(key)}="${safe(value)}"`).join("");
      return `<button type="button" class="action-btn" data-fill="${safe(JSON.stringify(fields || {}))}"${view ? ` data-view-target="${safe(view)}"` : ""}${action ? ` data-action="${safe(action)}"` : ""}${extra}>${safe(label)}</button>`;
    }
    function approvalAction(approval) {
      const id = approval?.id || "";
      if (id.startsWith("approval.admin.adapter.enable.")) return "approve-admin-adapter-enablement";
      if (id.startsWith("approval.admin.archive.")) return "approve-admin-archive";
      if (id.startsWith("approval.admin.restore.")) return "approve-admin-restore";
      if (id.startsWith("approval.admin.policy.warning.")) return "approve-policy-warning";
      if (id.startsWith("approval.claim.cleanup.")) return "approve-claim-cleanup";
      return "";
    }
    function adminPlanFill(planId) {
      return {
        "admin-approval-plan-id": planId || "",
        "admin-execute-plan-id": planId || "",
        "admin-cancel-plan-id": planId || "",
        "policy-warning-plan-id": planId || ""
      };
    }
    function maintenanceScheduleFill(row) {
      return {
        "maintenance-schedule-id": row?.id || "",
        "maintenance-schedule-target": row?.target || "",
        "maintenance-schedule-recurrence": row?.recurrence || "weekly",
        "maintenance-schedule-window": row?.window || "unscheduled",
        "maintenance-schedule-timezone": row?.timezone || "UTC",
        "maintenance-schedule-owner": row?.owner_domain || "obrien",
        "maintenance-schedule-risk": row?.risk_level || "medium",
        "maintenance-schedule-status": row?.status || "active",
        "maintenance-schedule-blackout": row?.blackout || "",
        "maintenance-schedule-validation": row?.validation || "",
        "maintenance-schedule-rollback": row?.rollback || "",
        "maintenance-schedule-notes": row?.notes || "",
        "maintenance-schedule-metadata": JSON.stringify(row?.metadata || {})
      };
    }
    function approvalFill(approval) {
      const id = approval?.id || "";
      const subject = approval?.subject_id || "";
      if (id.startsWith("approval.admin.adapter.enable.")) return {"admin-adapter-approval-id": id};
      if (id.startsWith("approval.admin.archive.")) return {"admin-archive-approval-id": id, "admin-archive-execute-approval-id": id};
      if (id.startsWith("approval.admin.restore.")) return {"admin-restore-approval-id": id, "admin-unarchive-approval-id": id};
      if (id.startsWith("approval.admin.policy.warning.")) return {"policy-warning-approval-id": id, "policy-warning-plan-id": subject.replace(/^admin\\.policy\\.warning\\./, "").split(".admin.")[0]};
      if (id.startsWith("approval.claim.cleanup.")) return {"cleanup-approval-id": id, "cleanup-execute-approval-id": id};
      if (id.includes("daemon-migration")) return crewDecisionFill("sisko", "Administrative decision", {subject: `Review ${id}`, message: approval.reason || ""});
      return {"admin-approval-plan-id": subject || id};
    }
    function crewDecisionFill(role, subject, values) {
      const prefix = rolePrefix(`${role}-${subject}`);
      return {
        [`${prefix}-subject`]: values.subject || subject,
        [`${prefix}-message`]: values.message || "",
        [`${prefix}-priority`]: values.priority || "medium",
        [`${prefix}-requested-by`]: values.requested_by || "operator",
        [`${prefix}-plan-id`]: values.plan_id || "",
        [`${prefix}-resource-id`]: values.resource_id || "",
        [`${prefix}-limit-id`]: values.limit_id || ""
      };
    }
    function operationFill(row) {
      return {
        "op-record-id": row.id || "",
        "op-transition-record-id": row.id || "",
        "op-kind": row.kind || "incident",
        "op-owner": row.owner_domain || "sisko",
        "op-status": row.status || "open",
        "op-transition-status": row.status || "open",
        "op-severity": row.severity || "low",
        "op-resource-id": row.resource_id || "",
        "op-subject": row.subject || "",
        "op-summary": row.summary || "",
        "op-next-step": row.next_step || "",
        "op-transition-next-step": row.next_step || "",
        "op-evidence-ids": (row.evidence_ids || []).join(", "),
        "op-metadata": JSON.stringify(row.metadata || {})
      };
    }
    function operationWorkflowFill(row) {
      return {
        "op-workflow-template-id": row.id || "",
        "op-workflow-record-id": `ops.${row.id || "workflow"}`,
        "op-workflow-resource-id": "",
        "op-workflow-requested-by": "sisko",
        "op-kind": row.kind || "incident",
        "op-owner": row.owner_domain || "sisko",
        "op-status": "staged",
        "op-severity": row.severity || "low",
        "op-subject": row.subject || "",
        "op-summary": row.summary || "",
        "op-next-step": row.next_step || "",
        "op-metadata": JSON.stringify({template_id: row.id || ""})
      };
    }
    function resourceClaimFill(resourceId, role = "dax") {
      return {
        "claim-resource-id": resourceId || "",
        "claim-owner-role": role || "dax",
        "claim-intent": `coordinate work on ${resourceId || "resource"}`,
        "claim-action": "review and deconflict requested work"
      };
    }
    function backupJobFill(row) {
      return {
        "backup-job-id": row?.id || "",
        "restore-job-id": row?.id || "",
        "backup-target": row?.target || "",
        "backup-schedule": row?.schedule || "manual",
        "backup-retention": row?.retention || "operator-defined",
        "backup-status": row?.status || "staged",
        "backup-risk": row?.risk_level || "medium",
        "backup-notes": row?.notes || ""
      };
    }
    function restoreTestFill(row) {
      return {
        "restore-test-id": row?.id || "",
        "restore-job-id": row?.job_id || "",
        "restore-point": row?.restore_point || "",
        "restore-status": row?.status || "planned",
        "restore-validated-by": row?.validated_by || "kira",
        "restore-notes": row?.notes || ""
      };
    }
    function backupCleanupFill(row) {
      return {
        "backup-cleanup-request-id": row?.id || "",
        "backup-cleanup-path": row?.path || "",
        "backup-cleanup-reason": row?.reason || row?.next_step || "review generated storage cleanup candidate",
        "backup-cleanup-approved-by": row?.approved_by || "kira",
        "backup-cleanup-executed-by": row?.executed_by || "kira"
      };
    }
    function backupExecutionFill(row) {
      return {
        "backup-exec-request-id": row?.id || "",
        "backup-exec-source-path": row?.source_path || "",
        "backup-exec-backup-name": row?.backup_name || row?.id || "",
        "backup-exec-reason": row?.reason || row?.next_step || "stage approved local backup execution",
        "backup-exec-approved-by": row?.approved_by || "kira",
        "backup-exec-executed-by": row?.executed_by || "kira"
      };
    }
    function restoreExecutionFill(row) {
      return {
        "restore-exec-request-id": row?.id || "",
        "restore-exec-backup-path": row?.backup_path || "",
        "restore-exec-restore-target": row?.restore_target || "artifacts/restore-test/local-state",
        "restore-exec-reason": row?.reason || row?.next_step || "stage approved local restore execution",
        "restore-exec-approved-by": row?.approved_by || "kira",
        "restore-exec-executed-by": row?.executed_by || "kira"
      };
    }
    function virtualRuntimeFill(row) {
      return {
        "virtual-resource-id": row?.resource_id || "",
        "virtual-kind": row?.kind || "vm",
        "virtual-state": row?.state || "observed",
        "virtual-adapter": row?.adapter || "manual",
        "virtual-ports": Array.isArray(row?.ports) ? row.ports.join(", ") : "",
        "virtual-snapshot-hint": row?.snapshot_hint || row?.snapshot_path || "",
        "virtual-notes": row?.notes || row?.next_step || "",
        "snapshot-resource-id": row?.resource_id || "",
        "restore-virtual-resource-id": row?.resource_id || "",
        "destroy-virtual-resource-id": row?.resource_id || ""
      };
    }
    function virtualSnapshotFill(row) {
      return {
        "snapshot-request-id": row?.id || "",
        "snapshot-resource-id": row?.resource_id || "",
        "snapshot-name": row?.snapshot_name || "",
        "snapshot-reason": row?.reason || row?.next_step || "stage virtual snapshot before maintenance",
        "snapshot-approved-by": row?.approved_by || "sisko",
        "snapshot-executed-by": row?.executed_by || "dax",
        "restore-virtual-resource-id": row?.resource_id || "",
        "restore-virtual-point": row?.snapshot_name || row?.id || ""
      };
    }
    function virtualRestoreFill(row) {
      return {
        "restore-virtual-request-id": row?.id || "",
        "restore-virtual-resource-id": row?.resource_id || "",
        "restore-virtual-point": row?.restore_point || "",
        "restore-virtual-reason": row?.reason || row?.next_step || "stage virtual restore after failed change",
        "restore-virtual-approved-by": row?.approved_by || "sisko",
        "restore-virtual-executed-by": row?.executed_by || "dax"
      };
    }
    function virtualDestroyFill(row) {
      return {
        "destroy-virtual-request-id": row?.id || "",
        "destroy-virtual-resource-id": row?.resource_id || "",
        "destroy-virtual-reason": row?.reason || row?.next_step || "stage virtual destroy after disposable target is no longer needed",
        "destroy-virtual-approved-by": row?.approved_by || "sisko",
        "destroy-virtual-executed-by": row?.executed_by || "dax"
      };
    }
    function imageScanFill(row) {
      return {
        "image-scan-request-id": row?.id || row?.request_id || "",
        "image-scan-image": row?.image || "",
        "image-scan-provider": row?.provider || "docker",
        "image-scan-scanner": row?.scanner || "trivy",
        "image-scan-requested-by": row?.requested_by || "dax",
        "image-scan-approved-by": row?.approved_by || "sisko",
        "image-scan-executed-by": row?.executed_by || "dax",
        "image-scan-reason": row?.reason || row?.next_step || "scan container image before production use"
      };
    }
    function claimFill(claimId) {
      return {
        "claim-approval-id": claimId || "",
        "claim-activate-id": claimId || "",
        "claim-release-id": claimId || "",
        "cleanup-claim-id": claimId || ""
      };
    }
    function cleanupFill(row) {
      return {
        "cleanup-claim-id": row?.id || "",
        "cleanup-approval-id": row?.approval_id || "",
        "cleanup-execute-approval-id": row?.approval_id || ""
      };
    }
    function listenerFill(row) {
      return {
        "security-listener": row?.listener || "",
        "security-plan-id": row?.plan_id || "",
        "security-remediation-reason": row?.next_step || "review exposed listener"
      };
    }
    function sourceReviewFill(row) {
      return {
        "source-remote-address": row?.remote_address || "",
        "source-listener": row?.listener || "",
        "source-disposition": row?.disposition || "needs_review",
        "source-rationale": row?.next_step || "review source activity"
      };
    }
    function firewallPolicyFill(row) {
      const index = row?.index ?? 0;
      return {
        "firewall-rule-index": index,
        "firewall-plan-id": `admin.firewall-policy.rule-${index}.${row?.action || "rule"}.${row?.port || "port"}`,
        "firewall-enforcement-reason": row?.next_step || "stage desired firewall policy enforcement for IDS review",
        "ids-plan-id": `admin.firewall-policy.rule-${index}.${row?.action || "rule"}.${row?.port || "port"}`
      };
    }
    function identityRotationFill(row) {
      return {
        "identity-rotation-request-id": row?.id || row?.request_id || "",
        "identity-rotation-subject": row?.subject || row?.path || row?.area || "",
        "identity-rotation-subject-type": row?.subject_type || "secret",
        "identity-rotation-urgency": row?.urgency || "medium",
        "identity-rotation-reason": row?.next_step || row?.reason || "stage identity or secret rotation review"
      };
    }
    function usageLimitFill(row) {
      return {
        "usage-limit-id": row?.limit_id || "",
        "usage-request-limit-id": row?.limit_id || "",
        "usage-resource-id": row?.resource_id || "",
        "usage-request-resource-id": row?.resource_id || "",
        "usage-capacity": row?.capacity ?? "",
        "usage-remaining": row?.remaining ?? "",
        "usage-resets-at": row?.resets_at || ""
      };
    }
    function serviceEvidenceFill(row) {
      return {
        "health-resource-id": row?.resource_id || "",
        "health-name": row?.name || row?.unit || "",
        "journal-resource-id": row?.resource_id || "",
        "journal-unit": row?.unit || "",
        "op-record-id": `ops.service.${row?.resource_id || "detail"}`,
        "op-kind": "service_detail",
        "op-owner": "julian",
        "op-status": "staged",
        "op-resource-id": row?.resource_id || "",
        "op-subject": `Service detail review: ${row?.resource_id || "resource"}`,
        "op-summary": row?.health_error || row?.next_step || "Review service evidence.",
        "op-next-step": row?.next_step || "review service detail evidence"
      };
    }
    function journalAccessFill(row) {
      return {
        "journal-resource-id": row?.resource_id || "",
        "journal-unit": row?.unit || "",
        "journal-reason": row?.next_step || "system journal access needed for service diagnosis",
        "journal-execute-record-id": `ops.service.journal-access.${row?.resource_id || "service"}`,
        "op-record-id": `ops.service.journal-access.${row?.resource_id || "service"}`,
        "op-kind": "service_detail",
        "op-owner": "julian",
        "op-status": "waiting_approval",
        "op-resource-id": row?.resource_id || "",
        "op-subject": `System journal access review: ${row?.resource_id || "service"}`,
        "op-summary": `Request read-only system journal evidence for ${row?.unit || row?.resource_id || "service"}.`,
        "op-next-step": "human approval required before privileged or system journal contents are read"
      };
    }
    function metricHistoryFill(row) {
      return {
        "metric-history-id": row?.id || "",
        "metric-history-notes": row?.next_step || "capture retained observability trends"
      };
    }
    function serviceValidationRows(items) {
      return (items || []).flatMap((item) => (item.validation_checklist || []).map((check) => ({
        resource_id: item.resource_id,
        step: check.step,
        status: check.status
      })));
    }
    function serviceLogRows(items) {
      return (items || []).flatMap((item) => (item.log_evidence || []).map((log) => ({
        resource_id: item.resource_id,
        target_id: log.target_id,
        path: log.path,
        readable: log.readable,
        lines: log.lines
      })));
    }
    function serviceJournalRows(items) {
      return (items || []).map((item) => ({
        resource_id: item.resource_id,
        unit: item.unit,
        available: item.journal_excerpt?.available,
        exit_code: item.journal_excerpt?.exit_code,
        error: item.journal_excerpt?.error || item.journal_excerpt?.reason || ""
      }));
    }
    function systemJournalCaptureRows(items) {
      return (items || []).flatMap((item) => (item.system_journal_captures || []).map((capture) => ({
        resource_id: item.resource_id,
        record_id: capture.record_id || `ops.service.journal-access.${item.resource_id || "service"}`,
        ...capture
      })));
    }
    function documentChildPath(folder, file) {
      const cleanFolder = String(folder || "").replace(/\\/+$/, "");
      const cleanFile = String(file || "").replace(/^\\/+/, "").replace(/\\/+$/, "");
      if (!cleanFolder) return cleanFile;
      if (!cleanFile) return cleanFolder;
      return `${cleanFolder}/${cleanFile}`;
    }
    function documentFileFill(row) {
      if (row?.kind === "folder") return {"documents-folder": row.path || ""};
      return {"documents-note-path": row?.path || row?.file || ""};
    }
    function workflowFill(row) {
      const source = row?.source || "";
      const folder = source.endsWith(".md") ? source.split("/").slice(0, -1).join("/") : source;
      return {
        "documents-note-path": source,
        "documents-folder": folder || "Overseer",
        "documents-query": row?.query || row?.workflow || source
      };
    }
    function domainView(domain) {
      const views = {
        sisko: "admin",
        kira: "assets",
        obrien: "admin",
        odo: "security",
        odo_ids: "security",
        odo_firewall: "security",
        quark: "usage",
        dax: "claims",
        julian: "health",
        ezri: "ezri"
      };
      return views[String(domain || "").toLowerCase()] || "audit";
    }
    function metric(label, value, hint, span = "span-3", tone = "", targetView = "") {
      const panelTone = normalizeTone(tone);
      const tag = targetView ? "button" : "div";
      const attrs = targetView ? ` type="button" data-view-target="${safe(targetView)}" title="Open ${safe(title(targetView))}"` : "";
      return `<${tag} class="panel metric ${span} ${panelTone}"${attrs}><h3>${safe(label)}</h3><div class="value ${toneClass(panelTone)}">${safe(value ?? 0)}</div><p class="muted">${safe(hint)}</p></${tag}>`;
    }
    function officerPanel(role, subject, prompt, relatedLimitId = "") {
      const prefix = rolePrefix(`${role}-${subject}`);
      const crewData = state.data.crewMessages || {};
      const crewCounts = ((crewData.by_owner_domain || {})[role]) || {};
      const messages = (crewData.items || []).filter((item) => item.owner_domain === role);
      const openMessages = messages.filter((item) => item.status === "open");
      const recentMessages = messages.slice(0, 5);
      const dispatches = (crewData.recent_dispatches || []).filter((item) => item.owner_domain === role);
      const blockedDispatches = dispatches.filter((item) => item.event_type === "blocked");
      return `<div class="panel span-12 officer-channel">
        <div class="toolbar"><h3>${safe(officerName(role))} Channel</h3><div class="actions"><button class="action-btn" data-action="dispatch-crew-messages" data-role="${safe(role)}">Dispatch Open</button><button class="action-btn" data-action="send-crew-message" data-role="${safe(role)}" data-prefix="${safe(prefix)}">Send Request</button></div></div>
        <div class="mini-metrics">
          <span class="pill">${safe(crewCounts.open ?? 0)} open</span>
          <span class="pill">${safe(crewCounts.dispatches ?? 0)} dispatched</span>
          <span class="pill ${crewCounts.blocked_dispatches ? "warn" : "good"}">${safe(crewCounts.blocked_dispatches ?? 0)} blocked</span>
        </div>
        <div class="form-grid">
          <div class="field span-3"><label for="${prefix}-subject">Subject</label><input id="${prefix}-subject" value="${safe(subject)}"></div>
          <div class="field span-2"><label for="${prefix}-priority">Priority</label><select id="${prefix}-priority">${riskOptions()}</select></div>
          <div class="field span-1"><label for="${prefix}-requested-by">By</label><input id="${prefix}-requested-by" value="operator"></div>
          <div class="field span-2"><label for="${prefix}-resource-id">Resource</label><input id="${prefix}-resource-id"></div>
          <div class="field span-2"><label for="${prefix}-plan-id">Plan</label><input id="${prefix}-plan-id"></div>
          <div class="field span-2"><label for="${prefix}-limit-id">Limit</label><input id="${prefix}-limit-id" value="${safe(relatedLimitId)}"></div>
          <div class="field span-6"><label for="${prefix}-message">Issue</label><textarea id="${prefix}-message">${safe(prompt)}</textarea></div>
          <div class="field span-6">${table("Open Queue", openMessages, ["id", "priority", "subject", "created_at"])}</div>
          <div class="field span-6">${table("Dispatch History", dispatches, ["occurred_at", "event_type", "message_id", "reason"])}</div>
          <div class="field span-6">${table("Blocked Reasons", blockedDispatches, ["occurred_at", "message_id", "reason"])}</div>
          <div class="field span-12">${table("Recent Requests", recentMessages, ["id", "priority", "status", "subject", "created_at"])}</div>
        </div>
      </div>`;
    }
    function rolePrefix(role) {
      return `crew-${String(role).replace(/[^a-z0-9]+/g, "-")}`;
    }
    function officerName(role) {
      const names = {
        sisko: "Sisko",
        kira: "Kira",
        obrien: "O'Brien",
        odo: "Odo",
        odo_ids: "Odo IDS",
        odo_firewall: "Odo Firewall",
        quark: "Quark",
        dax: "Dax",
        julian: "Julian",
        ezri: "Ezri"
      };
      return names[role] || labelize(role);
    }
    function crew(name, data) {
      const rows = Object.entries(data || {}).slice(0, 5).map(([key, value]) => `<div class="row"><span>${safe(labelize(key))}</span><strong>${safe(value ?? 0)}</strong></div>`).join("");
      const view = crewView(name);
      return `<button type="button" class="panel crew-card span-4" data-view-target="${safe(view)}" title="Open ${safe(name)} station"><h3>${safe(name)}</h3><p class="muted">${safe(crewStation(name))}</p><div class="list">${rows || "<p class='muted'>No data</p>"}</div></button>`;
    }
    function crewView(name) {
      const views = {
        "Sisko": "admin",
        "Kira": "assets",
        "O'Brien": "admin",
        "Odo": "security",
        "Odo IDS": "security",
        "Odo Firewall": "security",
        "Quark": "usage",
        "Dax": "claims",
        "Julian": "health",
        "Ezri": "ezri"
      };
      return views[name] || "overview";
    }
    function crewStation(name) {
      const stations = {
        "Sisko": "Command",
        "Kira": "Physical assets",
        "Kira / Dax": "Asset control",
        "O'Brien": "Maintenance",
        "Odo": "Security",
        "Odo IDS": "IDS and advisory review",
        "Odo Firewall": "Firewall management",
        "Quark": "Service limits",
        "Dax": "Virtual assets",
        "Julian": "Health",
        "Ezri": "Documentation"
      };
      return stations[name] || "Operations";
    }
    function table(titleText, rows, keys, options = {}) {
      const limit = options.limit ?? 12;
      const body = (rows || []).slice(0, limit).map((row) => `<tr>${keys.map((key) => `<td>${formatCell(row, key, options)}</td>`).join("")}</tr>`).join("");
      return `<div class="toolbar"><h3>${safe(titleText)}</h3><span class="pill">${(rows || []).length}</span></div><div class="table-scroll"><table><thead><tr>${keys.map((key) => `<th>${safe(labelize(key))}</th>`).join("")}</tr></thead><tbody>${body || `<tr><td colspan="${keys.length}" class="muted">No rows</td></tr>`}</tbody></table></div>`;
    }
    function formatCell(row, key, options = {}) {
      const value = row?.[key];
      const link = options.links?.[key];
      if (link) {
        const target = typeof link === "function" ? link(row, key, value) : link;
        if (target) return `<button type="button" class="cell-link" data-view-target="${safe(target)}">${format(value)}</button>`;
      }
      if (options.external?.[key]) {
        const external = options.external[key];
        const href = typeof external === "function" ? external(row, key, value) : value;
        if (href) return `<a class="cell-link" href="${safe(href)}" target="_blank" rel="noreferrer">${format(value)}</a>`;
      }
      const fill = options.fills?.[key];
      if (fill) {
        const fields = fill(row, key, value);
        const fillAction = options.fillActions?.[key];
        const action = typeof fillAction === "function" ? fillAction(row, key, value) : fillAction;
        if (fields) return `<button type="button" class="cell-link" data-fill="${safe(JSON.stringify(fields))}" data-view-target="${safe(options.fillView || state.view)}"${action ? ` data-action="${safe(action)}"` : ""}>${format(value)}</button>`;
      }
      return format(value);
    }
    function kv(titleText, value) {
      const rows = Object.entries(value || {}).slice(0, 12).map(([key, val]) => `<div class="row"><span>${safe(labelize(key))}</span><strong>${format(val)}</strong></div>`).join("");
      return `<h3>${safe(titleText)}</h3><div class="list">${rows || "<p class='muted'>No data</p>"}</div>`;
    }
    function title(view) {
      if (view === "driver") return "Primary AI Driver";
      return view.charAt(0).toUpperCase() + view.slice(1);
    }
    function labelize(key) {
      return String(key).replaceAll("_", " ");
    }
    function format(value) {
      if (value === null || value === undefined || value === "") return "<span class='muted'>none</span>";
      if (typeof value === "boolean") return value ? "<span class='pill good'>yes</span>" : "<span class='pill inactive'>no</span>";
      if (Array.isArray(value)) return safe(value.join(", "));
      if (typeof value === "object") return safe(JSON.stringify(value));
      const text = String(value);
      const cls = stateTone(text);
      return cls ? `<span class="pill ${cls}">${safe(text)}</span>` : safe(text);
    }
    function safe(value) {
      return String(value ?? "").replace(/[&<>"']/g, (char) => {
        if (char === "&") return "&amp;";
        if (char === "<") return "&lt;";
        if (char === ">") return "&gt;";
        if (char === '"') return "&quot;";
        return "&#39;";
      });
    }
    function slug(value) {
      return String(value ?? "item").toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "item";
    }
    function overallClass(value) {
      return stateTone(value) || "warn";
    }
    function toneClass(tone) {
      return tone === "bad" ? "bad-text" : tone === "warn" ? "warn-text" : tone === "good" ? "good-text" : tone === "pending" ? "pending-text" : tone === "inactive" ? "inactive-text" : "";
    }
    function freshnessTone(status) {
      if (status === "ok") return "good";
      if (status === "warning") return "warn";
      if (status === "high" || status === "missing") return "bad";
      return "";
    }
    function normalizeTone(tone) {
      return ["good", "warn", "bad", "pending", "inactive"].includes(tone) ? tone : "";
    }
    function stateTone(value) {
      const text = String(value ?? "").toLowerCase().replaceAll("_", " ");
      if (["ok", "pass", "passed", "enabled", "completed", "complete", "healthy", "ready", "accepted", "active", "running", "fresh"].includes(text)) return "good";
      if (["critical", "failed", "failure", "blocked", "error", "bad", "unhealthy", "missing", "rejected", "hostile"].includes(text)) return "bad";
      if (["warning", "warn", "pending", "queued", "submitted", "waiting", "stale", "revision required", "approval required", "needs review"].includes(text)) return "warn";
      if (["prepared", "requested", "open", "manual execution required", "ids review blocked"].includes(text)) return "pending";
      if (["disabled", "canceled", "cancelled", "archived", "inactive", "none", "not found", "unsupported"].includes(text)) return "inactive";
      return "";
    }
    const style = document.createElement("style");
    style.textContent = ".good-text{color:var(--good)}.warn-text{color:var(--warn)}.bad-text{color:var(--bad)}.pending-text{color:var(--pending)}.inactive-text{color:var(--inactive)}";
    document.head.appendChild(style);
    render();
    if (state.token) {
      refresh();
    } else {
      document.getElementById("updated").textContent = "enter Overseer API token";
    }
  </script>
</body>
</html>
"""
