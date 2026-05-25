const express = require('express');
const cors = require('cors');
const multer = require('multer');
const axios = require('axios');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
require('dotenv').config();
const { traceable } = require('langsmith/traceable');

const app = express();
const PORT = process.env.PORT || 5000;
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// Trust Vercel Proxy to ensure rate limiting uses the real client IP instead of the proxy IP
app.set('trust proxy', 1);

const REVIEW_PROFILES = [
  {
    id: 'balanced-default',
    name: 'Balanced Default',
    defaultReviewType: 'quality',
    promptBoost: 'Prioritize correctness, readability, and maintainability with practical fixes.'
  },
  {
    id: 'security-first',
    name: 'Security First',
    defaultReviewType: 'security',
    promptBoost: 'Focus heavily on vulnerability detection, exploitability, and secure coding standards.'
  },
  {
    id: 'performance-focused',
    name: 'Performance Focused',
    defaultReviewType: 'performance',
    promptBoost: 'Prioritize bottlenecks, complexity, memory footprint, and optimization opportunities.'
  },
  {
    id: 'interview-coach',
    name: 'Interview Coach',
    defaultReviewType: 'interview',
    promptBoost: 'Focus on edge cases, tradeoffs, clean abstractions, and interview-style recommendations.'
  }
];

const QUALITY_GATES = [
  {
    id: 'balanced-gate',
    name: 'Balanced Gate',
    minScore: 7,
    maxCritical: 0,
    maxHigh: 2
  },
  {
    id: 'strict-gate',
    name: 'Strict Gate',
    minScore: 8.5,
    maxCritical: 0,
    maxHigh: 0
  },
  {
    id: 'security-gate',
    name: 'Security Gate',
    minScore: 7.5,
    maxCritical: 0,
    maxHigh: 1
  }
];

const DEFAULT_PROFILE_ID = 'balanced-default';
const DEFAULT_QUALITY_GATE_ID = 'balanced-gate';
const REVIEW_PROFILE_MAP = new Map(REVIEW_PROFILES.map((profile) => [profile.id, profile]));
const QUALITY_GATE_MAP = new Map(QUALITY_GATES.map((gate) => [gate.id, gate]));
const PROFILE_DEFAULT_GATE_MAP = {
  'balanced-default': 'balanced-gate',
  'security-first': 'security-gate',
  'performance-focused': 'strict-gate',
  'interview-coach': 'balanced-gate'
};

const sanitizeTags = (tags) => {
  if (!Array.isArray(tags)) return [];
  return tags
    .map((tag) => String(tag || '').trim())
    .filter(Boolean)
    .slice(0, 20);
};

const countBySeverity = (items = [], severity = 'critical') =>
  items.filter((item) => String(item?.severity || '').toLowerCase() === severity).length;

const evaluateQualityGate = (review, gate) => {
  const score = Number(review?.score || 0);
  const bugs = review?.bugs || [];
  const securityIssues = review?.securityIssues || [];
  const performanceIssues = review?.performanceIssues || [];
  const codeQualityIssues = review?.codeQualityIssues || [];
  const allIssues = [...bugs, ...securityIssues, ...performanceIssues, ...codeQualityIssues];

  const criticalCount = countBySeverity(allIssues, 'critical');
  const highCount = countBySeverity(allIssues, 'high');

  const checks = {
    score: score >= gate.minScore,
    critical: criticalCount <= gate.maxCritical,
    high: highCount <= gate.maxHigh
  };

  const passed = Object.values(checks).every(Boolean);

  return {
    id: gate.id,
    name: gate.name,
    passed,
    checks,
    metrics: {
      score,
      criticalCount,
      highCount
    },
    evaluatedAt: new Date().toISOString()
  };
};

const allowedOrigins = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

const corsOptions = {
  origin: (origin, callback) => {
    // Allow non-browser requests (like curl/Postman) or development mode
    if (!origin || !IS_PRODUCTION) return callback(null, true);
    
    // In production, strictly enforce CORS to prevent other sites from burning your LLM tokens
    if (allowedOrigins.length > 0 && (allowedOrigins.includes(origin) || allowedOrigins.includes('*'))) {
      return callback(null, true);
    }
    return callback(new Error('CORS not allowed - Unauthorized Origin'));
  },
  methods: ['GET', 'POST'],
  credentials: false,
};

const apiLimiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000),
  max: Number(process.env.RATE_LIMIT_MAX || 100),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again later.' }
});

// Middleware
app.use(helmet());
app.use(compression());
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use('/api', apiLimiter);

// File upload configuration
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'text/x-c', 'text/x-c++', 'text/x-java', 'text/x-python',
      'text/javascript', 'text/typescript', 'text/html', 'text/css',
      'text/x-sql', 'application/javascript', 'application/json',
      '.c', '.cpp', '.h', '.hpp', '.java', '.py', '.js', '.jsx',
      '.ts', '.tsx', '.html', '.css', '.sql', '.json', '.xml'
    ];
    
    const ext = '.' + file.originalname.split('.').pop().toLowerCase();
    const isValid = allowedTypes.some(type => 
      file.mimetype.includes(type) || ext === type
    );
    
    if (isValid) {
      cb(null, true);
    } else {
      cb(new Error('Unsupported file type'), false);
    }
  }
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  let dbConnected = false;
  try {
    await prisma.$queryRaw`SELECT 1`;
    dbConnected = true;
  } catch (e) {}

  const health = {
    status: dbConnected ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.round(process.uptime()),
    environment: process.env.NODE_ENV || 'development',
    services: {
      gemini: !!process.env.GEMINI_API_KEY,
      groq: !!process.env.GROQ_API_KEY,
      postgres: dbConnected
    }
  };

  if (!dbConnected) {
    return res.status(503).json(health);
  }

  res.json({
    ...health
  });
});

// AI Review prompt template
const createReviewPrompt = (code, language, reviewType, profilePrompt = '') => {
  const reviewTypeInstructions = {
    'beginner': 'Explain concepts in simple terms suitable for someone learning to code. Focus on basic programming concepts and common pitfalls.',
    'bug': 'Focus specifically on identifying bugs, errors, and logical mistakes in the code. Provide specific line numbers and fixes.',
    'quality': 'Analyze code quality, maintainability, readability, and adherence to best practices. Focus on code structure and organization.',
    'security': 'Identify security vulnerabilities, potential exploits, injection attacks, and recommend security best practices. Focus on OWASP guidelines.',
    'performance': 'Analyze performance bottlenecks, algorithmic efficiency, memory usage, and provide optimization suggestions. Include time and space complexity analysis.',
    'interview': 'Review code as if preparing for a technical interview. Focus on edge cases, problem-solving approach, and alternative solutions.'
  };

  const instruction = reviewTypeInstructions[reviewType] || reviewTypeInstructions['quality'];

  return `You are a strict but helpful senior code reviewer. Analyze the following ${language} code and provide a comprehensive review.

Review Type: ${reviewType.toUpperCase()}
${instruction}

Additional Profile Guidance:
${profilePrompt || 'Use balanced judgment across quality, correctness, and maintainability.'}

Code to review:
\`\`\`${language.toLowerCase()}
${code}
\`\`\`

Respond ONLY with a valid JSON object in this exact structure (no markdown, no explanation outside JSON):
{
  "score": number (0-10, where 10 is perfect),
  "summary": "Brief overall assessment of the code",
  "bugs": [
    {
      "line": number or "N/A",
      "issue": "Description of the bug",
      "severity": "low|medium|high|critical",
      "fix": "How to fix this bug",
      "originalSnippet": "Exact lines of original code to replace, or null",
      "fixedSnippet": "Corrected code to replace the original snippet, or null"
    }
  ],
  "securityIssues": [
    {
      "line": number or "N/A",
      "issue": "Description of security vulnerability",
      "severity": "low|medium|high|critical",
      "recommendation": "Security recommendation",
      "originalSnippet": "Exact lines of original code to replace, or null",
      "fixedSnippet": "Corrected code to replace the original snippet, or null"
    }
  ],
  "performanceIssues": [
    {
      "line": number or "N/A",
      "issue": "Description of performance problem",
      "severity": "low|medium|high|critical",
      "suggestion": "Optimization suggestion",
      "originalSnippet": "Exact lines of original code to replace, or null",
      "fixedSnippet": "Corrected code to replace the original snippet, or null"
    }
  ],
  "codeQualityIssues": [
    {
      "line": number or "N/A",
      "issue": "Description of code quality issue",
      "severity": "low|medium|high|critical",
      "suggestion": "Improvement suggestion",
      "originalSnippet": "Exact lines of original code to replace, or null",
      "fixedSnippet": "Corrected code to replace the original snippet, or null"
    }
  ],
  "bestPractices": [
    "Best practice recommendation 1",
    "Best practice recommendation 2"
  ],
  "improvedCode": "The complete improved code with all fixes applied, wrapped in triple backticks with the language identifier",
  "explanation": "Detailed explanation of all changes made and why",
  "timeComplexity": "Time complexity analysis (e.g., O(n), O(n^2))",
  "spaceComplexity": "Space complexity analysis (e.g., O(1), O(n))",
  "testCases": [
    {
      "input": "Test input description",
      "expectedOutput": "Expected output description",
      "description": "What this test case validates"
    }
  ],
  "securityRiskLevel": "none|low|medium|high|critical"
}

Ensure all arrays are present even if empty. The improvedCode must be a valid, complete code snippet that can be directly used.`;
};

// Mongoose Review model replaced by Prisma

// Rule-based fallback review used when AI providers are unavailable.
const generateMockReview = (codeSample, lang, type) => {
  const code = String(codeSample || '');
  const lower = code.toLowerCase();
  const codeLines = code.split('\n');

  const bugs = [];
  const securityIssues = [];
  const performanceIssues = [];
  const codeQualityIssues = [];

  if (/\b==\b/.test(code) && !/===/.test(code) && lang === 'JavaScript') {
    bugs.push({
      line: 'N/A',
      issue: 'Loose equality (`==`) can cause coercion bugs.',
      severity: 'medium',
      fix: 'Use strict equality (`===`) and explicit conversions when needed.'
    });
  }

  if ((lang === 'Python' || lang === 'JavaScript') && /\/(\s*)[a-zA-Z_][a-zA-Z0-9_]*/.test(code) && !/\bif\b.*\b0\b/.test(lower)) {
    bugs.push({
      line: 'N/A',
      issue: 'Potential divide-by-zero path is not visibly guarded.',
      severity: 'high',
      fix: 'Validate denominator before division and return/throw a controlled error.'
    });
  }

  if (/\beval\s*\(/.test(lower) || /\bexec\s*\(/.test(lower)) {
    securityIssues.push({
      line: 'N/A',
      issue: 'Dynamic code execution detected (`eval`/`exec`).',
      severity: 'critical',
      recommendation: 'Remove dynamic execution and use safe parsing/dispatch strategies.'
    });
  }

  if (/innerhtml\s*=/.test(lower) || /document\.write\s*\(/.test(lower)) {
    securityIssues.push({
      line: 'N/A',
      issue: 'Potential XSS sink detected (raw HTML injection).',
      severity: 'high',
      recommendation: 'Use safe DOM APIs/textContent and sanitize untrusted input.'
    });
  }

  if (/password\s*=\s*['"][^'"]+['"]/.test(code) || /api[_-]?key\s*=\s*['"][^'"]+['"]/i.test(code)) {
    securityIssues.push({
      line: 'N/A',
      issue: 'Hardcoded secret-like value detected in code.',
      severity: 'high',
      recommendation: 'Move secrets to environment variables or secret manager.'
    });
  }

  if (/for\s*\(.*\)\s*\{?[\s\S]{0,120}for\s*\(/.test(code)) {
    performanceIssues.push({
      line: 'N/A',
      issue: 'Nested loops may become expensive on large inputs.',
      severity: 'medium',
      suggestion: 'Consider indexing, memoization, or reducing nested iterations.'
    });
  }

  if (/(console\.log\(|print\()/.test(code) && type !== 'beginner') {
    codeQualityIssues.push({
      line: 'N/A',
      issue: 'Debug output detected in primary code path.',
      severity: 'low',
      suggestion: 'Use structured logging with levels or remove debug statements before release.'
    });
  }

  if (codeLines.length > 120) {
    codeQualityIssues.push({
      line: 'N/A',
      issue: 'Large snippet detected; maintainability may suffer.',
      severity: 'medium',
      suggestion: 'Split into smaller functions/modules with single responsibilities.'
    });
  }

  if (!/try\s*\{|catch\s*\(/.test(code) && (lang === 'JavaScript' || lang === 'Python')) {
    codeQualityIssues.push({
      line: 'N/A',
      issue: 'No explicit error handling pattern detected.',
      severity: 'low',
      suggestion: 'Add guarded error handling around I/O or risky operations.'
    });
  }

  const allIssues = [...bugs, ...securityIssues, ...performanceIssues, ...codeQualityIssues];
  const highAndCritical = allIssues.filter((item) => ['high', 'critical'].includes(String(item.severity || '').toLowerCase())).length;

  let score = 9.2;
  score -= bugs.length * 0.7;
  score -= securityIssues.length * 1.1;
  score -= performanceIssues.length * 0.6;
  score -= codeQualityIssues.length * 0.4;
  score = Math.max(1, Math.min(10, Number(score.toFixed(1))));

  let securityRiskLevel = 'none';
  if (securityIssues.some((item) => item.severity === 'critical')) securityRiskLevel = 'critical';
  else if (securityIssues.some((item) => item.severity === 'high')) securityRiskLevel = 'high';
  else if (securityIssues.some((item) => item.severity === 'medium')) securityRiskLevel = 'medium';
  else if (securityIssues.length > 0) securityRiskLevel = 'low';

  const summary = allIssues.length
    ? `Fallback analysis for ${lang}: found ${allIssues.length} issue(s), including ${highAndCritical} high/critical risk item(s).`
    : `Fallback analysis for ${lang}: no major issues detected in this snippet.`;

  const languageTag = (lang || 'text').toLowerCase();
  const improvedCode = [
    '```' + languageTag,
    '// Suggested improvements (fallback mode):',
    '// 1) Add explicit input validation and edge-case handling.',
    '// 2) Replace unsafe/dynamic patterns with deterministic logic.',
    '// 3) Add error handling around risky operations.',
    code,
    '```'
  ].join('\n');

  return {
    score,
    summary,
    bugs,
    securityIssues,
    performanceIssues,
    codeQualityIssues,
    bestPractices: [
      'Validate all external/user-controlled inputs.',
      'Add focused unit tests for edge cases and failure paths.',
      'Use clear naming and keep functions small and single-purpose.'
    ],
    improvedCode,
    explanation: 'This review was generated by a local rule-based fallback because AI provider review was unavailable. Configure working provider keys for full AI review depth.',
    timeComplexity: 'Depends on implementation details; inspect loops and nested operations.',
    spaceComplexity: 'Depends on data structures used by the snippet.',
    testCases: [
      {
        input: 'Nominal valid input',
        expectedOutput: 'Correct functional result',
        description: 'Verifies happy-path behavior.'
      },
      {
        input: 'Edge input (null/empty/zero)',
        expectedOutput: 'Graceful handling without crash',
        description: 'Verifies robustness on boundary conditions.'
      }
    ],
    securityRiskLevel
  };
};

// Parse AI response to extract JSON
const parseAIResponse = (text) => {
  try {
    // Try direct JSON parse
    return JSON.parse(text);
  } catch (e) {
    // Try to extract JSON from markdown code blocks
    const jsonMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/) ||
                      text.match(/\{[\s\S]*\}/);
    
    if (jsonMatch) {
      try {
        const jsonStr = jsonMatch[1] || jsonMatch[0];
        return JSON.parse(jsonStr);
      } catch (e2) {
        console.error('Failed to parse extracted JSON:', e2);
      }
    }
    
    throw new Error('Could not parse AI response as JSON');
  }
};

const PROVIDER_LIMIT_COOLDOWN_MS = Number(process.env.PROVIDER_LIMIT_COOLDOWN_MS || 60 * 1000);
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-2.0-flash';
const GROQ_MODEL = process.env.GROQ_MODEL || 'llama-3.1-8b-instant';
const providerCooldownUntil = {
  gemini: 0,
  groq: 0
};

const isProviderCoolingDown = (provider) => Date.now() < (providerCooldownUntil[provider] || 0);

const putProviderOnCooldown = (provider, ms = PROVIDER_LIMIT_COOLDOWN_MS) => {
  providerCooldownUntil[provider] = Date.now() + Math.max(1000, Number(ms) || PROVIDER_LIMIT_COOLDOWN_MS);
};

const extractErrorMessage = (error) => {
  if (!error) return '';
  return String(
    error?.message ||
    error?.response?.data?.error?.message ||
    error?.response?.data?.error ||
    ''
  ).toLowerCase();
};

const isLimitError = (error) => {
  const status = Number(error?.response?.status || 0);
  const message = extractErrorMessage(error);
  return (
    status === 429 ||
    status === 503 ||
    message.includes('quota') ||
    message.includes('rate limit') ||
    message.includes('resource_exhausted') ||
    message.includes('too many requests')
  );
};

const getProviderOrder = () => {
  const hasGemini = Boolean(process.env.GEMINI_API_KEY);
  const hasGroq = Boolean(process.env.GROQ_API_KEY);

  const ready = [];
  const cooling = [];

  if (hasGemini) {
    (isProviderCoolingDown('gemini') ? cooling : ready).push('gemini');
  }
  if (hasGroq) {
    (isProviderCoolingDown('groq') ? cooling : ready).push('groq');
  }

  return [...ready, ...cooling];
};

const getReviewWithProviderSwitching = async (code, language, reviewType, profilePrompt) => {
  const order = getProviderOrder();
  const attemptedProviders = [];
  let lastError = null;

  for (const provider of order) {
    attemptedProviders.push(provider);

    try {
      if (provider === 'gemini') {
        const result = await getGeminiReview(code, language, reviewType, profilePrompt);
        return {
          result,
          reviewSource: 'gemini',
          attemptedProviders,
          switchedByLimit: attemptedProviders.length > 1
        };
      }

      if (provider === 'groq') {
        const result = await getGroqReview(code, language, reviewType, profilePrompt);
        return {
          result,
          reviewSource: 'groq',
          attemptedProviders,
          switchedByLimit: attemptedProviders.length > 1
        };
      }
    } catch (providerError) {
      lastError = providerError;
      console.error(`${provider} API error:`, providerError.message);

      if (isLimitError(providerError)) {
        putProviderOnCooldown(provider);
        continue;
      }

      // Non-limit failures should still allow trying the next provider when available.
      continue;
    }
  }

  return {
    result: generateMockReview(code, language, reviewType),
    reviewSource: 'local-fallback',
    attemptedProviders,
    switchedByLimit: attemptedProviders.length > 1 && Boolean(lastError && isLimitError(lastError))
  };
};

// Gemini API integration
const getGeminiReview = traceable(async (code, language, reviewType, profilePrompt) => {
  const { GoogleGenerativeAI } = require('@google/generative-ai');
  const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });
  
  const prompt = createReviewPrompt(code, language, reviewType, profilePrompt);
  const result = await model.generateContent(prompt);
  const response = await result.response;
  const text = response.text();
  
  return parseAIResponse(text);
}, { name: 'getGeminiReview' });

// Groq API integration
const getGroqReview = traceable(async (code, language, reviewType, profilePrompt) => {
  const prompt = createReviewPrompt(code, language, reviewType, profilePrompt);
  
  const response = await axios.post(
    'https://api.groq.com/openai/v1/chat/completions',
    {
      model: GROQ_MODEL,
      response_format: { type: 'json_object' },
      messages: [
        {
          role: 'system',
          content: 'You are a strict but helpful senior code reviewer. Always respond with valid JSON only.'
        },
        {
          role: 'user',
          content: prompt
        }
      ],
      temperature: 0.3,
      max_tokens: 4096
    },
    {
      headers: {
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
        'Content-Type': 'application/json'
      }
    }
  );
  
  return parseAIResponse(response.data.choices[0].message.content);
}, { name: 'getGroqReview' });

// Code review endpoint
app.post('/api/review-code', async (req, res) => {
  try {
    const { code, language, reviewType, profileId, qualityGateId, tags = [] } = req.body;
    const normalizedLanguage = String(language || '').trim();
    const normalizedReviewType = reviewType ? String(reviewType).trim() : '';
    const normalizedProfileId = profileId ? String(profileId).trim() : '';
    const normalizedQualityGateId = qualityGateId ? String(qualityGateId).trim() : '';
    const normalizedTags = sanitizeTags(tags);

    // Validation
    if (!code || code.trim() === '') {
      return res.status(400).json({ error: 'Code is required' });
    }

    if (!normalizedLanguage) {
      return res.status(400).json({ error: 'Language is required' });
    }

    const validLanguages = ['C', 'C++', 'Java', 'Python', 'JavaScript', 'TypeScript', 'HTML', 'CSS', 'SQL'];
    if (!validLanguages.includes(normalizedLanguage)) {
      return res.status(400).json({ error: 'Unsupported language' });
    }

    const validReviewTypes = ['beginner', 'bug', 'quality', 'security', 'performance', 'interview'];
    if (normalizedReviewType && !validReviewTypes.includes(normalizedReviewType)) {
      return res.status(400).json({ error: 'Invalid review type' });
    }

    if (normalizedProfileId && !REVIEW_PROFILE_MAP.has(normalizedProfileId)) {
      return res.status(400).json({
        error: 'Invalid profileId',
        allowedProfileIds: REVIEW_PROFILES.map((profile) => profile.id)
      });
    }

    if (normalizedQualityGateId && !QUALITY_GATE_MAP.has(normalizedQualityGateId)) {
      return res.status(400).json({
        error: 'Invalid qualityGateId',
        allowedQualityGateIds: QUALITY_GATES.map((gate) => gate.id)
      });
    }

    const selectedProfile = REVIEW_PROFILE_MAP.get(normalizedProfileId || DEFAULT_PROFILE_ID) || REVIEW_PROFILES[0];
    const resolvedQualityGateId = normalizedQualityGateId || PROFILE_DEFAULT_GATE_MAP[selectedProfile.id] || DEFAULT_QUALITY_GATE_ID;
    const selectedGate = QUALITY_GATE_MAP.get(resolvedQualityGateId) || QUALITY_GATES[0];
    const effectiveReviewType = normalizedReviewType || selectedProfile.defaultReviewType;

    const reviewEngineResult = await getReviewWithProviderSwitching(
      code,
      normalizedLanguage,
      effectiveReviewType,
      selectedProfile.promptBoost
    );

    const result = reviewEngineResult.result;
    const reviewSource = reviewEngineResult.reviewSource;

    const qualityGate = evaluateQualityGate(result, selectedGate);

    const responsePayload = {
      ...result,
      reviewType: effectiveReviewType,
      reviewProfile: { id: selectedProfile.id, name: selectedProfile.name },
      qualityGate,
      reviewSource,
      attemptedProviders: reviewEngineResult.attemptedProviders,
      switchedByLimit: reviewEngineResult.switchedByLimit,
      tags: normalizedTags
    };

    res.json(responsePayload);
    // Persist review to Postgres via Prisma
    try {
      await prisma.review.create({
        data: {
          code,
          language: normalizedLanguage,
          reviewType: effectiveReviewType,
          profileId: selectedProfile.id,
          qualityGateId: selectedGate.id,
          qualityGateStatus: qualityGate.passed ? 'passed' : 'failed',
          tags: normalizedTags,
          result: responsePayload
        }
      });
    } catch (dbErr) {
      console.error('Failed to save review to DB:', dbErr.message);
    }
  } catch (error) {
    console.error('Review error:', error);
    res.status(500).json({ 
      error: 'Failed to process code review',
      details: error.message 
    });
  }
});

// List recent reviews (for debugging and UI)
app.get('/api/reviews', async (req, res) => {
  try {
    const {
      q,
      language,
      reviewType,
      profileId,
      gateStatus,
      sort = 'latest',
      page = '1',
      pageSize = '20'
    } = req.query;

    const pageNumber = Math.max(Number(page) || 1, 1);
    const perPage = Math.min(Math.max(Number(pageSize) || 20, 1), 100);

    const where = {};
    if (language) where.language = language;
    if (reviewType) where.reviewType = reviewType;
    if (profileId) where.profileId = profileId;
    if (gateStatus) where.qualityGateStatus = gateStatus;
    if (q) where.code = { contains: q, mode: 'insensitive' };

    const [total, reviews] = await Promise.all([
      prisma.review.count({ where }),
      prisma.review.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: (pageNumber - 1) * perPage,
        take: perPage
      })
    ]);

    let finalReviews = reviews;
    if (sort === 'score') {
      finalReviews.sort((a, b) => Number(b.result?.score || 0) - Number(a.result?.score || 0));
    }

    res.json({
      reviews: finalReviews,
      pagination: {
        total,
        page: pageNumber,
        pageSize: perPage,
        totalPages: Math.ceil(total / perPage)
      }
    });
  } catch (err) {
    console.error('Failed to fetch reviews:', err.message);
    res.status(500).json({ error: 'Failed to fetch reviews' });
  }
});

app.get('/api/review-profiles', (req, res) => {
  res.json({
    profiles: REVIEW_PROFILES,
    qualityGates: QUALITY_GATES
  });
});

app.get('/api/analytics', async (req, res) => {
  try {
    const days = Math.min(Math.max(Number(req.query.days) || 14, 1), 90);
    const from = new Date();
    from.setDate(from.getDate() - days);

    const reviews = await prisma.review.findMany({
      where: { createdAt: { gte: from } },
      select: { reviewType: true, qualityGateStatus: true, result: true, createdAt: true }
    });

    const totalReviews = reviews.length;
    const totalScore = reviews.reduce((acc, review) => acc + Number(review?.result?.score || 0), 0);
    const passedCount = reviews.filter((review) => review.qualityGateStatus === 'passed').length;

    const criticalIssues = reviews.reduce((acc, review) => {
      const result = review.result || {};
      const allIssues = [
        ...(result.bugs || []),
        ...(result.securityIssues || []),
        ...(result.performanceIssues || []),
        ...(result.codeQualityIssues || [])
      ];
      return acc + countBySeverity(allIssues, 'critical');
    }, 0);

    const distributionMap = reviews.reduce((acc, review) => {
      const key = review.reviewType || 'unknown';
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});

    const scoreTrendMap = reviews.reduce((acc, review) => {
      const dayKey = new Date(review.createdAt).toISOString().slice(0, 10);
      if (!acc[dayKey]) acc[dayKey] = { totalScore: 0, count: 0 };
      acc[dayKey].totalScore += Number(review?.result?.score || 0);
      acc[dayKey].count += 1;
      return acc;
    }, {});

    const reviewTypeDistribution = Object.entries(distributionMap).map(([name, value]) => ({
      name,
      value
    }));

    const scoreTrend = Object.entries(scoreTrendMap)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([date, value]) => ({
        date,
        avgScore: Number((value.totalScore / value.count).toFixed(2)),
        reviews: value.count
      }));

    res.json({
      summary: {
        totalReviews,
        averageScore: totalReviews ? Number((totalScore / totalReviews).toFixed(2)) : 0,
        gatePassRate: totalReviews ? Number(((passedCount / totalReviews) * 100).toFixed(1)) : 0,
        criticalIssues
      },
      reviewTypeDistribution,
      scoreTrend
    });
  } catch (err) {
    console.error('Failed to build analytics:', err.message);
    res.status(500).json({ error: 'Failed to build analytics' });
  }
});

// File upload endpoint
app.post('/api/upload-code', upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const content = req.file.buffer.toString('utf-8');
    const filename = req.file.originalname;
    const extension = filename.split('.').pop().toLowerCase();

    // Map extension to language
    const languageMap = {
      'c': 'C',
      'cpp': 'C++',
      'h': 'C',
      'hpp': 'C++',
      'java': 'Java',
      'py': 'Python',
      'js': 'JavaScript',
      'jsx': 'JavaScript',
      'ts': 'TypeScript',
      'tsx': 'TypeScript',
      'html': 'HTML',
      'css': 'CSS',
      'sql': 'SQL',
      'json': 'JavaScript'
    };

    res.json({
      content,
      filename,
      language: languageMap[extension] || 'JavaScript'
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to process file upload' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 5MB.' });
    }
    return res.status(400).json({ error: err.message });
  }
  
  if (err.message === 'Unsupported file type') {
    return res.status(400).json({ 
      error: 'Unsupported file type. Please upload a valid code file (C, C++, Java, Python, JavaScript, TypeScript, HTML, CSS, SQL).' 
    });
  }
  
  res.status(500).json({ error: 'Internal server error' });
});

let server;
const startServer = () => {
  server = app.listen(PORT, () => {
    console.log(`🚀 AI Code Reviewer backend running on port ${PORT}`);
    console.log(`   Health check: http://localhost:${PORT}/api/health`);

    if (!process.env.GEMINI_API_KEY && !process.env.GROQ_API_KEY) {
      console.warn('⚠️  Warning: No AI API key configured. Please add GEMINI_API_KEY or GROQ_API_KEY to your .env file.');
    }
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`❌ Port ${PORT} is already in use. Stop the other process or set a different PORT.`);
      process.exit(1);
    }

    console.error('❌ Server startup error:', err.message);
    process.exit(1);
  });
};

const shutdown = async (signal) => {
  console.log(`\n${signal} received. Shutting down gracefully...`);
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
  await prisma.$disconnect();
  process.exit(0);
};

process.on('SIGINT', () => {
  shutdown('SIGINT').catch((err) => {
    console.error('Shutdown error:', err.message);
    process.exit(1);
  });
});

process.on('SIGTERM', () => {
  shutdown('SIGTERM').catch((err) => {
    console.error('Shutdown error:', err.message);
    process.exit(1);
  });
});

if (require.main === module) {
  startServer();
}

module.exports = app;
