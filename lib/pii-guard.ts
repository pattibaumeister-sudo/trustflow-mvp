export interface PIIPattern {
  name: string;
  regex: RegExp;
  mask: (match: string) => string;
}

export const GERMAN_PII_PATTERNS: PIIPattern[] = [
  // E-Mail-Adressen
  {
    name: 'EMAIL',
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    mask: () => '[EMAIL_REDACTED]',
  },
  // Deutsche Telefonnummern
  {
    name: 'PHONE_DE',
    regex: /(?:\+49|0)[1-9][0-9]{1,4}[\s\/-]?[0-9]{3,8}/g,
    mask: () => '[PHONE_REDACTED]',
  },
  // Deutsche Steuer-ID (11-stellig)
  {
    name: 'TAX_ID_DE',
    regex: /\b[0-9]{2}[\s\/-]?[0-9]{3}[\s\/-]?[0-9]{3}[\s\/-]?[0-9]{3}\b/g,
    mask: () => '[TAX_ID_REDACTED]',
  },
  // IBAN (Fokus DE)
  {
    name: 'IBAN_DE',
    regex: /\bDE[0-9]{2}[\s]?[0-9]{4}[\s]?[0-9]{4}[\s]?[0-9]{4}[\s]?[0-9]{4}[\s]?[0-9]{2}\b/gi,
    mask: () => '[IBAN_REDACTED]',
  },
];

export class PIIGuardEngine {
  private patterns: PIIPattern[];

  constructor(customPatterns?: PIIPattern[]) {
    this.patterns = customPatterns || GERMAN_PII_PATTERNS;
  }

  public sanitize(text: string): { sanitizedText: string; detectedCount: number } {
    let sanitizedText = text;
    let detectedCount = 0;

    for (const pattern of this.patterns) {
      const matches = sanitizedText.match(pattern.regex);
      if (matches) {
        detectedCount += matches.length;
        sanitizedText = sanitizedText.replace(pattern.regex, pattern.mask);
      }
    }

    return { sanitizedText, detectedCount };
  }
}
