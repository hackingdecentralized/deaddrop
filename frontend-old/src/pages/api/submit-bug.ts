import type { NextApiRequest, NextApiResponse } from 'next';

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'POST') {
    // Simulate accepting the bug report
    return res.status(200).json({ success: true });
  }
  res.status(405).json({ error: 'Method not allowed' });
} 