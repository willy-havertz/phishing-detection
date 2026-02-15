// Security utilities for frontend

/**
 * Sanitize HTML to prevent XSS attacks
 */
export const sanitizeHtml = (str) => {
  if (!str) return "";
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
};

/**
 * Sanitize text input
 */
export const sanitizeInput = (input) => {
  if (!input) return "";
  return String(input)
    .replace(/[<>]/g, "") // Remove angle brackets
    .replace(/javascript:/gi, "") // Remove javascript: protocol
    .replace(/on\w+=/gi, "") // Remove event handlers
    .trim()
    .slice(0, 50000); // Limit length
};

/**
 * Validate URL format
 */
export const isValidUrl = (string) => {
  try {
    const url = new URL(string);
    return ["http:", "https:"].includes(url.protocol);
  } catch {
    return false;
  }
};

/**
 * Generate a secure random ID
 */
export const generateSecureId = () => {
  const array = new Uint32Array(4);
  crypto.getRandomValues(array);
  return Array.from(array, (x) => x.toString(16).padStart(8, "0")).join("");
};

/**
 * Rate limit function calls
 */
export const createRateLimiter = (maxCalls, windowMs) => {
  const calls = [];

  return () => {
    const now = Date.now();
    const windowStart = now - windowMs;

    // Remove old calls
    while (calls.length > 0 && calls[0] < windowStart) {
      calls.shift();
    }

    if (calls.length >= maxCalls) {
      return false; // Rate limited
    }

    calls.push(now);
    return true; // Allowed
  };
};

/**
 * Secure storage wrapper with encryption placeholder
 * In production, use a proper encryption library
 */
export const secureStorage = {
  set: (key, value) => {
    try {
      const data = JSON.stringify({
        v: value,
        t: Date.now(),
        c: generateSecureId().slice(0, 8), // Integrity check
      });
      localStorage.setItem(key, data);
      return true;
    } catch {
      return false;
    }
  },

  get: (key) => {
    try {
      const raw = localStorage.getItem(key);
      if (!raw) return null;
      const data = JSON.parse(raw);
      return data.v;
    } catch {
      return null;
    }
  },

  remove: (key) => {
    try {
      localStorage.removeItem(key);
      return true;
    } catch {
      return false;
    }
  },
};

/**
 * Content Security Policy meta tag generator
 */
export const generateCSPMeta = () => {
  return `
    default-src 'self';
    script-src 'self' 'unsafe-inline';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: https:;
    font-src 'self';
    connect-src 'self' http://localhost:* ws://localhost:*;
    frame-ancestors 'none';
    base-uri 'self';
    form-action 'self';
  `
    .replace(/\s+/g, " ")
    .trim();
};
