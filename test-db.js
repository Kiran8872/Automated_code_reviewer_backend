const { Client } = require('pg');

const client = new Client({
  user: 'postgres.odupxuknolmbzibmxvvi',
  password: 'kiran@887217',
  host: 'aws-1-ap-southeast-2.pooler.supabase.com',
  port: 5432,
  database: 'postgres',
});

async function test() {
  try {
    console.log('Connecting to Supabase (object config)...');
    await client.connect();
    console.log('Connected successfully!');
    await client.end();
  } catch (e) {
    console.error('Connection error:', e.message);
  }
}
test();
