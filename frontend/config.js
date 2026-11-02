// The frontend calls the API on the same origin (/api/...).
// On Vercel, vercel.json proxies /api/* to the Render backend.
// Locally, the FastAPI server serves this folder itself.
// Only set this if you host the frontend somewhere without a proxy.
window.API_BASE = window.API_BASE || "";
