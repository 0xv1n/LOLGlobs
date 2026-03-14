(function () {
  'use strict';

  var searchInput = document.getElementById('search-input');
  var noResults = document.getElementById('no-results');
  var resultsCount = document.getElementById('results-count');
  var clearSearch = document.getElementById('clear-search');
  var platformTabs = document.querySelectorAll('.tab-btn');
  var categoryChips = document.querySelectorAll('.chip');

  if (!searchInput || !window.LOLGLOB_ENTRIES) return;

  var state = { query: '', platform: 'all', category: 'all' };

  // Augment entries with display element references + original text snapshots
  window.LOLGLOB_ENTRIES.forEach(function (entry) {
    entry.nameEl  = entry.el.querySelector('.entry-link');
    entry.descEl  = entry.el.querySelector('.col-desc-text');
    entry.nameOrig = entry.nameEl  ? entry.nameEl.textContent  : '';
    entry.descOrig = entry.descEl  ? entry.descEl.textContent  : '';
  });

  // ---- Highlight helpers ----
  function escHtml(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  function highlightText(original, query) {
    if (!query || !original) return escHtml(original || '');
    var escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    var re = new RegExp('(' + escaped + ')', 'gi');
    return escHtml(original).replace(re, '<mark class="search-hl">$1</mark>');
  }

  function applyHighlights(entry, text) {
    if (entry.nameEl && entry.nameOrig !== undefined)
      entry.nameEl.innerHTML = highlightText(entry.nameOrig, text);
    if (entry.descEl && entry.descOrig !== undefined)
      entry.descEl.innerHTML = highlightText(entry.descOrig, text);
  }

  function clearHighlights(entry) {
    if (entry.nameEl && entry.nameOrig !== undefined)
      entry.nameEl.textContent = entry.nameOrig;
    if (entry.descEl && entry.descOrig !== undefined)
      entry.descEl.textContent = entry.descOrig;
  }

  // ---- Platform / chip helpers ----
  function setActivePlatformTab(platform) {
    platformTabs.forEach(function (t) {
      var active = t.dataset.platform === platform;
      t.classList.toggle('active', active);
      t.setAttribute('aria-selected', String(active));
    });
  }

  function setActiveChip(category) {
    categoryChips.forEach(function (c) {
      c.classList.toggle('active', c.dataset.category === category);
    });
  }

  // Parse prefixes: @platform, /category
  function parseQuery(raw) {
    var q = raw.trim();
    var platform = null;
    var category = null;
    var text = q;

    var platformMatch = q.match(/^@([\w-]+)\s*(.*)/);
    if (platformMatch) {
      platform = platformMatch[1];
      text = platformMatch[2];
    }

    var catMatch = text.match(/^\/([\w-]+)\s*(.*)/);
    if (catMatch) {
      category = catMatch[1];
      text = catMatch[2];
    }

    return { platform: platform, category: category, text: text.toLowerCase() };
  }

  function filter() {
    var raw = searchInput.value;
    var parsed = parseQuery(raw);

    // Prefix overrides tab/chip state
    var activePlatform = parsed.platform || state.platform;
    var activeCategory = parsed.category || state.category;
    var text = parsed.text;
    var isMitre = text && /^t\d/i.test(text);

    // Sync UI if prefix changed state
    if (parsed.platform) setActivePlatformTab(parsed.platform);
    if (parsed.category) setActiveChip(parsed.category);

    var visible = 0;
    var entries = window.LOLGLOB_ENTRIES;
    var total = entries.length;

    entries.forEach(function (entry) {
      var show = true;

      if (activePlatform !== 'all' && entry.platform !== activePlatform) show = false;
      if (activeCategory !== 'all' && entry.category !== activeCategory) show = false;

      if (show && text) {
        if (isMitre) {
          show = entry.mitre.toLowerCase().indexOf(text) !== -1;
        } else {
          show = entry.name.indexOf(text) !== -1 ||
                 entry.desc.indexOf(text) !== -1 ||
                 entry.mitre.toLowerCase().indexOf(text) !== -1;
        }
      }

      entry.el.style.display = show ? '' : 'none';
      if (show) visible++;

      // Highlighting: only on visible rows with a non-MITRE text query
      if (text && !isMitre && show) {
        applyHighlights(entry, text);
      } else {
        clearHighlights(entry);
      }
    });

    if (visible === total && !text && activePlatform === 'all' && activeCategory === 'all') {
      resultsCount.textContent = total + ' entries';
    } else {
      resultsCount.textContent = visible + ' of ' + total + ' entries';
    }

    noResults.style.display = visible === 0 ? '' : 'none';
  }

  searchInput.addEventListener('input', function () {
    filter();
    if (history.replaceState) {
      var q = searchInput.value;
      history.replaceState(null, '', q ? '#search=' + encodeURIComponent(q) : location.pathname + location.search);
    }
  });

  platformTabs.forEach(function (tab) {
    tab.addEventListener('click', function () {
      setActivePlatformTab(tab.dataset.platform);
      state.platform = tab.dataset.platform;
      if (searchInput.value.startsWith('@')) searchInput.value = '';
      filter();
    });
  });

  categoryChips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      setActiveChip(chip.dataset.category);
      state.category = chip.dataset.category;
      if (searchInput.value.startsWith('/')) searchInput.value = '';
      filter();
    });
  });

  if (clearSearch) {
    clearSearch.addEventListener('click', function (e) {
      e.preventDefault();
      searchInput.value = '';
      state = { query: '', platform: 'all', category: 'all' };
      setActivePlatformTab('all');
      setActiveChip('all');
      filter();
    });
  }

  // '/' shortcut to focus search
  document.addEventListener('keydown', function (e) {
    if (e.key === '/' && document.activeElement !== searchInput &&
        document.activeElement.tagName !== 'INPUT' &&
        document.activeElement.tagName !== 'TEXTAREA') {
      e.preventDefault();
      searchInput.focus();
      searchInput.select();
    }
    if (e.key === 'Escape' && document.activeElement === searchInput) {
      searchInput.blur();
    }
  });

  // Restore from URL hash
  var hashMatch = location.hash.match(/^#search=(.+)/);
  if (hashMatch) {
    searchInput.value = decodeURIComponent(hashMatch[1]);
  }

  filter();
})();
