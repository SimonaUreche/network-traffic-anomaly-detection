/** Mapare cod ISO 2 litere → nume în română (afișare lizibilă în UI). */
const ISO2_RO = {
  RO: 'România',
  US: 'Statele Unite',
  NL: 'Țările de Jos',
  GB: 'Regatul Unit',
  DE: 'Germania',
  FR: 'Franța',
  IT: 'Italia',
  ES: 'Spania',
  PL: 'Polonia',
  UA: 'Ucraina',
  RU: 'Rusia',
  CN: 'China',
  IN: 'India',
  BR: 'Brazilia',
  CA: 'Canada',
  AU: 'Australia',
  JP: 'Japonia',
  SE: 'Suedia',
  CH: 'Elveția',
  AT: 'Austria',
  BE: 'Belgia',
  CZ: 'Cehia',
  HU: 'Ungaria',
  BG: 'Bulgaria',
  MD: 'Republica Moldova',
};

/**
 * Afișează țara lizibil: nume complet + cod, sau mesaj pentru rețea locală.
 */
export function formatCountryDisplay(abuse = {}, whois = {}) {
  const raw = (whois.country != null && whois.country !== '')
    ? String(whois.country).trim()
    : (abuse.country != null ? String(abuse.country).trim() : '');

  if (!raw || raw === 'N/A' || raw === 'error') return '—';

  const upper = raw.toUpperCase();
  if (upper === 'LOCAL') return 'Rețea locală (laborator)';

  // Deja e nume lung (ex. "United States") — afișăm ca atare
  if (raw.length > 3 || raw.includes(' ')) return raw;

  const code = upper.length === 2 ? upper : null;
  if (code && ISO2_RO[code]) return `${ISO2_RO[code]} (${code})`;

  return raw;
}
