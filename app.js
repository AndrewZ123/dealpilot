const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- BASIC SETUP ----------
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: 'CHANGE_THIS_SECRET',
    resave: false,
    saveUninitialized: false
  })
);

app.use(express.static('public'));

// Simple template injector
const render = (res, view, vars = {}) => {
  const layout = fs.readFileSync(path.join(__dirname, 'views', 'layout.html'), 'utf8');
  let content = fs.readFileSync(path.join(__dirname, 'views', view + '.html'), 'utf8');

  let html = layout.replace('{{content}}', content);

  Object.entries(vars).forEach(([key, value]) => {
    const regex = new RegExp('{{' + key + '}}', 'g');
    html = html.replace(regex, value);
  });

  res.send(html);
};

const renderPage = (req, res, view, vars = {}) => {
  const isAuthed = Boolean(req.session?.userId);

  const navLinks = isAuthed
    ? `
      <a href="/" class="nav-link">Deals</a>
      <a href="/deals/new" class="nav-link">Post Deal</a>
      <a href="/redirects/new" class="nav-link">Add Redirect</a>
      <a href="/dashboard" class="nav-link">Dashboard</a>
    `
    : `
      <a href="/" class="nav-link">Deals</a>
    `;

  const navAuth = isAuthed
    ? `
      <span class="chip">${escapeHtml(req.session.username || 'Member')}</span>
      <a class="btn btn-solid" href="/logout">Logout</a>
    `
    : `
      <a class="btn btn-solid" href="/login">Member Login</a>
    `;

  render(res, view, {
    title: vars.title || 'DealPilot',
    nav_links: navLinks,
    nav_auth: navAuth,
    ...vars
  });
};

// ---------- USERS ----------
const USERS = [
  { id: 1, username: 'andrew', password: 'changeme1' },
  { id: 2, username: 'tony', password: 'changeme2' },
  { id: 3, username: 'underwrld', password: 'changeme3' },
  { id: 4, username: 'bed', password: 'changeme4' },
  { id: 5, username: 'sami', password: 'changeme5' },
  { id: 6, username: 'dbill', password: 'changeme6' },
  { id: 7, username: 'snowku', password: 'changeme7' },
  { id: 8, username: 'rios', password: 'changeme8' }
];

// ---------- DB SETUP ----------
const db = new sqlite3.Database(path.join(__dirname, 'dealpilot.db'));

db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS redirects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      slug TEXT NOT NULL,
      target_url TEXT NOT NULL,
      click_count INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE (user_id, slug)
    );`,
    (err) => {
      if (err) {
        console.error('Redirects table initialization error:', err);
      }
    }
  );

  db.run(
    `CREATE TABLE IF NOT EXISTS deals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      content TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`,
    (err) => {
      if (err) {
        console.error('Deals table initialization error:', err);
        return;
      }

      db.all(`PRAGMA table_info(deals);`, (pragmaErr, columns) => {
        if (pragmaErr) {
          console.error('Database introspection error:', pragmaErr);
          return;
        }

        const hasUserId = columns.some(col => col.name === 'user_id');

        const bootServer = () => {
          console.log('Database initialized successfully');
          app.listen(PORT, () => {
            console.log(`DealPilot running on http://localhost:${PORT}`);
          });
        };

        if (!hasUserId) {
          db.run(`ALTER TABLE deals ADD COLUMN user_id INTEGER;`, (alterErr) => {
            if (alterErr) {
              console.error('Failed adding user_id column to deals table:', alterErr);
              return;
            }
            bootServer();
          });
        } else {
          bootServer();
        }
      });
    }
  );
});

// ---------- MIDDLEWARE ----------
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

// ---------- HELPERS ----------
function generateSlug(length = 6) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let slug = '';
  for (let i = 0; i < length; i++) {
    slug += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return slug;
}

function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function hostFromUrl(url) {
  try {
    const hostname = new URL(url).hostname || '';
    return hostname.replace(/^www\./, '');
  } catch (err) {
    return url;
  }
}

function truncateCopy(text, limit = 180) {
  if (!text) return '';
  return text.length > limit ? text.slice(0, limit).trimEnd() + '...' : text;
}

// ---------- ROUTES ----------

// PUBLIC HOME PAGE (DEALS FEED)
app.get('/', (req, res) => {
  db.all(`SELECT * FROM deals ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) return res.status(500).send('Server error');

    let dealsHtml = '';
    const FTC = `<div class="notice notice-inline"><strong>FTC</strong><span>This post contains affiliate links. We may earn a commission when you click or buy.</span></div>`;

    rows.forEach(deal => {
      const safe = escapeHtml(deal.content);

      const clickable = safe.replace(
        /(https?:\/\/[^\s]+)/g,
        '<a href="$1" target="_blank" rel="nofollow noopener sponsored">$1</a>'
      );

      const adminButtons = req.session.userId ? `
        <div class="deal-actions">
          <a href="/deals/${deal.id}/edit" class="btn btn-ghost btn-compact">Edit</a>
          <form action="/deals/${deal.id}/delete" method="POST" style="display:inline;" onsubmit="return confirm('Delete this deal?');">
            <button type="submit" class="btn btn-danger btn-compact">Delete</button>
          </form>
        </div>
      ` : '';

      dealsHtml += `
        <article class="deal-card">
          ${FTC}
          <p class="deal-meta">${new Date(deal.created_at).toLocaleString()}</p>
          <div class="deal-text">${clickable}</div>
          ${adminButtons}
        </article>
      `;
    });

    renderPage(req, res, 'home', {
      title: 'DealPilot - Deals',
      deals: dealsHtml || '<p>No deals yet.</p>'
    });
  });
});

// LOGIN
app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  renderPage(req, res, 'login', { title: 'Login - DealPilot', error: '' });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const user = USERS.find(u => u.username === username && u.password === password);
  if (!user) {
    return renderPage(req, res, 'login', {
      title: 'Login - DealPilot',
      error: 'Invalid username or password.'
    });
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  res.redirect('/dashboard');
});

// LOGOUT
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// DASHBOARD
app.get('/dashboard', requireLogin, (req, res) => {
  const userId = req.session.userId;
  const safeUser = escapeHtml(req.session.username || 'Member');

  db.all(
    `SELECT id, slug, target_url, click_count, created_at
     FROM redirects
     WHERE user_id = ?
     ORDER BY created_at DESC`,
    [userId],
    (redirectErr, redirects = []) => {
      if (redirectErr) {
        console.error('Redirect fetch error:', redirectErr);
        return res.status(500).send('Server error');
      }

      db.all(
        `SELECT id, content, created_at
         FROM deals
         WHERE user_id = ?
         ORDER BY created_at DESC`,
        [userId],
        (dealErr, deals = []) => {
          if (dealErr) {
            console.error('Deal fetch error:', dealErr);
            return res.status(500).send('Server error');
          }

          db.get(`SELECT COUNT(*) AS total_deals FROM deals`, [], (totalDealErr, totalDealRow = { total_deals: 0 }) => {
            if (totalDealErr) {
              console.error('Deal count error:', totalDealErr);
              return res.status(500).send('Server error');
            }

            db.get(`SELECT COUNT(*) AS total_redirects FROM redirects`, [], (totalRedirectErr, totalRedirectRow = { total_redirects: 0 }) => {
              if (totalRedirectErr) {
                console.error('Redirect count error:', totalRedirectErr);
                return res.status(500).send('Server error');
              }

              const totalClicks = redirects.reduce((sum, row) => sum + (row.click_count || 0), 0);
              const topRedirect = [...redirects].sort((a, b) => (b.click_count || 0) - (a.click_count || 0))[0];

              const statCards = `
                <div class="stat-card">
                  <p class="stat-label">Clicks tracked</p>
                  <p class="stat-value">${totalClicks}</p>
                  <p class="stat-note">Across ${redirects.length} live links</p>
                </div>
                <div class="stat-card">
                  <p class="stat-label">Redirects live</p>
                  <p class="stat-value">${redirects.length}</p>
                  <p class="stat-note">${totalRedirectRow.total_redirects || 0} across network</p>
                </div>
                <div class="stat-card">
                  <p class="stat-label">Deals published</p>
                  <p class="stat-value">${deals.length}</p>
                  <p class="stat-note">${totalDealRow.total_deals || 0} public posts</p>
                </div>
              `;

              const redirectRows = redirects.length
                ? redirects
                    .map((row) => {
                      const shortLink = `https://dealpilot.org/${userId}/${row.slug}`;
                      return `
                        <div class="table-row">
                          <div>
                            <p class="mono-link">/${userId}/${escapeHtml(row.slug)}</p>
                            <small>${escapeHtml(hostFromUrl(row.target_url))}</small>
                          </div>
                          <div class="table-cell hide-mobile">
                            <a href="${escapeHtml(row.target_url)}" target="_blank" rel="noopener" class="pill pill-ghost">${escapeHtml(hostFromUrl(row.target_url))}</a>
                          </div>
                          <div>
                            <span class="pill">${row.click_count || 0} clicks</span>
                          </div>
                          <div>
                            <span class="muted">${new Date(row.created_at).toLocaleDateString()}</span>
                          </div>
                          <div>
                            <div class="action-cluster">
                              <a href="${escapeHtml(shortLink)}" target="_blank" rel="noopener" class="btn btn-outline btn-compact">Open</a>
                              <button type="button" class="btn btn-ghost btn-compact btn-copy" data-copy="${escapeHtml(shortLink)}">Copy</button>
                            </div>
                          </div>
                          <div>
                            <form action="/redirects/${row.id}/delete" method="POST" onsubmit="return confirm('Delete this redirect?');">
                              <button type="submit" class="btn btn-outline-danger btn-compact">Delete</button>
                            </form>
                          </div>
                        </div>
                      `;
                    })
                    .join('')
                : '<div class="empty-state">No redirects yet. Create one to start tracking clicks.</div>';

              const dealRows = deals.length
                ? deals
                    .map((deal) => {
                      return `
                        <article class="owned-deal">
                          <div class="owned-deal-head">
                            <p class="muted">Published ${new Date(deal.created_at).toLocaleDateString()}</p>
                          </div>
                          <p class="owned-deal-copy">${escapeHtml(truncateCopy(deal.content, 260))}</p>
                          <div class="owned-deal-actions">
                            <a href="/deals/${deal.id}/edit" class="btn btn-ghost btn-compact">Edit</a>
                            <form action="/deals/${deal.id}/delete" method="POST" onsubmit="return confirm('Delete this deal?');">
                              <button type="submit" class="btn btn-danger btn-compact">Delete</button>
                            </form>
                          </div>
                        </article>
                      `;
                    })
                    .join('')
                : '<div class="empty-state">You have not posted any deals yet.</div>';

              const highlightCopy = topRedirect
                ? `Top performing link <strong>/${userId}/${escapeHtml(topRedirect.slug)}</strong> has generated <strong>${topRedirect.click_count || 0}</strong> clicks.`
                : 'Launch a redirect to start capturing clicks and compliance logs.';

              renderPage(req, res, 'dashboard', {
                title: 'Dashboard',
                username: safeUser,
                stat_cards: statCards,
                redirect_rows: redirectRows,
                deal_rows: dealRows,
                highlight_copy: highlightCopy
              });
            });
          });
        }
      );
    }
  );
});

// NEW DEAL PAGE
app.get('/deals/new', requireLogin, (req, res) => {
  renderPage(req, res, 'new_deal', { title: 'Post Deal', error: '' });
});

// SUBMIT DEAL (ONE TEXTBOX)
app.post('/deals/new', requireLogin, (req, res) => {
  const { content } = req.body;

  if (!content || content.trim() === "") {
    return renderPage(req, res, 'new_deal', {
      title: 'Post Deal',
      error: 'Content is required.'
    });
  }

  db.run(
    `INSERT INTO deals (user_id, content) VALUES (?, ?)`,
    [req.session.userId, content.trim()],
    function(err) {
      if (err) {
        console.error('Deal insertion error:', err);
        return renderPage(req, res, 'new_deal', {
          title: 'Post Deal',
          error: 'Database error: ' + err.message
        });
      }
      res.redirect('/');
    }
  );
});

// NEW REDIRECT FORM
app.get('/redirects/new', requireLogin, (req, res) => {
  renderPage(req, res, 'new_redirect', {
    title: 'New Redirect',
    error: '',
    result: ''
  });
});

// CREATE A NEW REDIRECT (AUTO SLUG + AUTO COPY)
app.post('/redirects/new', requireLogin, (req, res) => {
  const userId = req.session.userId;
  const { target_url } = req.body;

  if (!target_url) {
    return renderPage(req, res, 'new_redirect', {
      title: 'New Redirect',
      error: 'Target URL required.',
      result: ''
    });
  }

  function attempt() {
    const slug = generateSlug(6);

    db.run(
      `INSERT INTO redirects (user_id, slug, target_url)
       VALUES (?, ?, ?)`,
      [userId, slug, target_url.trim()],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE')) return attempt();
          return renderPage(req, res, 'new_redirect', {
            title: 'New Redirect',
            error: 'Error creating redirect.',
            result: ''
          });
        }

        const link = `https://dealpilot.org/${userId}/${slug}`;
        const safeLink = escapeHtml(link);
        return renderPage(req, res, 'new_redirect', {
          title: 'New Redirect',
          error: '',
          result: `<a href="${safeLink}" target="_blank" rel="noopener noreferrer">${safeLink}</a>`
        });
      }
    );
  }

  attempt();
});

app.post('/redirects/:id/delete', requireLogin, (req, res) => {
  const redirectId = parseInt(req.params.id, 10);
  const userId = req.session.userId;

  if (isNaN(redirectId)) {
    return res.redirect('/dashboard');
  }

  db.run(
    `DELETE FROM redirects WHERE id = ? AND user_id = ?`,
    [redirectId, userId],
    function (err) {
      if (err) {
        console.error('Redirect deletion error:', err);
      }
      res.redirect('/dashboard');
    }
  );
});

// REDIRECT HANDLER
app.get('/:userId/:slug', (req, res) => {
  const userId = parseInt(req.params.userId);
  const slug = req.params.slug;

  if (isNaN(userId)) return res.status(404).send('Invalid');

  db.get(
    `SELECT * FROM redirects WHERE user_id = ? AND slug = ?`,
    [userId, slug],
    (err, row) => {
      if (!row) return res.status(404).send('Not found');

      db.run(`UPDATE redirects SET click_count = click_count + 1 WHERE id = ?`, [row.id], () => {});

      res.redirect(row.target_url);
    }
  );
});

// EDIT DEAL PAGE
app.get('/deals/:id/edit', requireLogin, (req, res) => {
  const dealId = parseInt(req.params.id);

  db.get(`SELECT * FROM deals WHERE id = ?`, [dealId], (err, deal) => {
    if (err || !deal) {
      return res.status(404).send('Deal not found');
    }

    renderPage(req, res, 'edit_deal', {
      title: 'Edit Deal',
      error: '',
      deal_id: deal.id,
      content: escapeHtml(deal.content)
    });
  });
});

// UPDATE DEAL
app.post('/deals/:id/edit', requireLogin, (req, res) => {
  const dealId = parseInt(req.params.id);
  const { content } = req.body;

  if (!content || content.trim() === "") {
    db.get(`SELECT * FROM deals WHERE id = ?`, [dealId], (err, deal) => {
      return renderPage(req, res, 'edit_deal', {
        title: 'Edit Deal',
        error: 'Content is required.',
        deal_id: dealId,
        content: escapeHtml(deal?.content || '')
      });
    });
    return;
  }

  db.run(
    `UPDATE deals SET content = ? WHERE id = ?`,
    [content.trim(), dealId],
    function(err) {
      if (err) {
        console.error('Deal update error:', err);
        return res.status(500).send('Database error');
      }
      res.redirect('/');
    }
  );
});

// DELETE DEAL
app.post('/deals/:id/delete', requireLogin, (req, res) => {
  const dealId = parseInt(req.params.id);

  db.run(`DELETE FROM deals WHERE id = ?`, [dealId], function(err) {
    if (err) {
      console.error('Deal deletion error:', err);
      return res.status(500).send('Database error');
    }
    res.redirect('/');
  });
});
