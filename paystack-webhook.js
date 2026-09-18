// Vercel serverless function.
// Paystack calls this URL after a payment event. We:
//   1. Check the request really came from Paystack (HMAC signature check)
//   2. Re-verify the transaction directly with Paystack's API (belt & braces —
//      never trust a webhook body alone for something as important as "did they pay")
//   3. Flip profiles.paid = true for that buyer using the service role key
//      (which bypasses row-level security — this is the one place that's safe)

import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';

export const config = { api: { bodyParser: false } };

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

function buffer(readable) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    readable.on('data', (chunk) => chunks.push(chunk));
    readable.on('end', () => resolve(Buffer.concat(chunks)));
    readable.on('error', reject);
  });
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).send('Method not allowed');
    return;
  }

  const buf = await buffer(req);
  const signature = req.headers['x-paystack-signature'];

  const expectedSignature = crypto
    .createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
    .update(buf)
    .digest('hex');

  if (signature !== expectedSignature) {
    console.error('Paystack webhook signature mismatch — request rejected.');
    res.status(400).send('Invalid signature');
    return;
  }

  const event = JSON.parse(buf.toString('utf8'));

  if (event.event === 'charge.success') {
    const reference = event.data && event.data.reference;
    const userId = event.data && event.data.metadata && event.data.metadata.user_id;

    if (!reference || !userId) {
      console.warn('charge.success missing reference or metadata.user_id — cannot process.');
      res.status(200).json({ received: true });
      return;
    }

    // Re-verify directly with Paystack rather than trusting the webhook body alone
    const verifyRes = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }
    });
    const verifyJson = await verifyRes.json();

    const paidOk =
      verifyJson &&
      verifyJson.data &&
      verifyJson.data.status === 'success';

    if (!paidOk) {
      console.warn('Paystack verify did not confirm success for reference:', reference);
      res.status(200).json({ received: true });
      return;
    }

    const { error } = await supabase
      .from('profiles')
      .update({ paid: true })
      .eq('id', userId);

    if (error) {
      console.error('Failed to mark profile as paid:', error.message);
      res.status(500).send('Database update failed');
      return;
    }
  }

  res.status(200).json({ received: true });
}
