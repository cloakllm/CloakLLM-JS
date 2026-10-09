/**
 * US ZIP codes in address context (v0.13.0, health edition).
 *
 * Off by default and OPT-IN: ShieldConfig.detectZipCodes must be `true`.
 * A ZIP is detected only after "City, ST", a full state name, or a ZIP /
 * postal-code label; only the ZIP itself is replaced. zipMode 'zip3' gives
 * the Safe Harbor form (first three digits + "XX", or "000XX" for a
 * restricted three-digit area).
 *
 * Mirrors cloakllm-py's cloakllm/clinical_geo.py exactly; see that module for
 * the reasoning behind each rule.
 */

const STATE_ABBR = 'AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|'
  + 'NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC|PR|GU|VI|AS|MP';
const STATE_NAMES = String.raw`Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|`
  + String.raw`Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|`
  + String.raw`Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New\sHampshire|New\sJersey|`
  + String.raw`New\sMexico|New\sYork|North\sCarolina|North\sDakota|Ohio|Oklahoma|Oregon|Pennsylvania|`
  + String.raw`Rhode\sIsland|South\sCarolina|South\sDakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|`
  + String.raw`West\sVirginia|Wisconsin|Wyoming|District\sof\sColumbia|Puerto\sRico`;
const ZIP_VALUE = String.raw`(\d{5}(?:-\d{4})?)(?![\d-])`;

const ZIP_PATTERN = String.raw`(?:(?<![A-Za-z])[A-Z][A-Za-z.'-]*,\s?(?:` + STATE_ABBR + String.raw`)\.?\s{1,2}`
  + String.raw`|\b(?:` + STATE_NAMES + String.raw`)\s{1,2}`
  + String.raw`|(?<![A-Za-z0-9])(?:ZIP|Zip|zip)(?:\s?(?:[Cc]ode|\+4))?\s{0,3}[:#]?\s{0,3}`
  + String.raw`|(?<![A-Za-z0-9])[Pp]ostal\s[Cc]ode\s{0,3}[:#]?\s{0,3}`
  + ')' + ZIP_VALUE;

/** HHS OCR FAQ 3.1, Census 2000. A default, overridable via zip3Restricted. */
const DEFAULT_ZIP3_RESTRICTED = new Set([
  '036', '059', '063', '102', '203', '556', '692', '790', '821',
  '823', '830', '831', '878', '879', '884', '890', '893',
]);

/** Safe Harbor form of a ZIP. Mirrors clinical_geo.zip3. */
function zip3(value, restricted = null) {
  const set = restricted == null ? DEFAULT_ZIP3_RESTRICTED : restricted;
  const prefix = value.slice(0, 3);
  return (set.has(prefix) ? '000' : prefix) + 'XX';
}

module.exports = { ZIP_PATTERN, DEFAULT_ZIP3_RESTRICTED, zip3 };
