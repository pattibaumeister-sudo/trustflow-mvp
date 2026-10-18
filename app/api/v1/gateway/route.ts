import { NextRequest, NextResponse } from 'next/server';
import { PIIGuardEngine } from '@/lib/pii-guard';

const piiGuard = new PIIGuardEngine();

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { prompt } = body;

    if (!prompt || typeof prompt !== 'string') {
      return NextResponse.json({ error: 'Valid prompt is required' }, { status: 400 });
    }

    // 1. PII Maskierung vor Ausführung
    const { sanitizedText, detectedCount } = piiGuard.sanitize(prompt);

    // 2. Anonymisierter Payload an das LLM weiterleiten
    return NextResponse.json({
      success: true,
      originalPromptLength: prompt.length,
      sanitizedPrompt: sanitizedText,
      piiBlockedCount: detectedCount,
      complianceNote: 'PII filtered before processing in accordance with GDPR/DSGVO.',
    });
  } catch (error) {
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
