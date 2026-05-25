require('dotenv').config();
const axios = require('axios');
const GROQ_MODEL = process.env.GROQ_MODEL || 'llama-3.1-8b-instant';

(async () => {
  try {
    if (!process.env.GROQ_API_KEY) {
      console.log('groq_key_present=false');
      return;
    }

    console.log('groq_key_present=true');

    const response = await axios.post(
      'https://api.groq.com/openai/v1/chat/completions',
      {
        model: GROQ_MODEL,
        messages: [{ role: 'user', content: 'Reply with exactly OK' }],
        max_tokens: 10,
        temperature: 0,
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
          'Content-Type': 'application/json',
        },
      }
    );

    console.log('groq_call_success=true');
    console.log(`groq_reply=${String(response.data?.choices?.[0]?.message?.content || '').trim()}`);
  } catch (error) {
    console.log('groq_call_success=false');
    console.log(`groq_error=${error?.response?.data?.error?.message || error?.message || 'unknown'}`);
    console.log(`groq_status=${error?.response?.status || 'n/a'}`);
  }
})();
