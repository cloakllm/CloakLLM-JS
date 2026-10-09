// Role-gated and header-line names (v0.13.0, health edition).
//
// Off by default: config.detectRoleNames (opt-in, must be === true). Mirrors
// cloakllm-py cloakllm/clinical_names.py exactly -- the pattern strings are
// byte-identical (checked from the Python suite).
//
// Targets three patterns that left names partly or wholly in place on the
// synthetic clinical benchmark: a name after a role word ("Patient Hector
// Vance."), a name heading a line of identifiers ("Lucia Pruitt 876701408"),
// and a surname that is also a disease eponym ("Thomas Parkinson", where
// only "Thomas" was removed). The first two are regex rules emitted as
// PERSON; the third is surname completion on NER results (extendFirstName).
'use strict';

const _HONORIFIC = '(?:Mr|Mrs|Ms|Mx|Miss|Dr|Prof)\\.?';
const _ROLE = (
  '(?:[Pp]atient(?:\\s[Nn]ame)?|[Pp]t\\.?(?:\\s[Nn]ame)?|[Nn]ame(?=\\s{0,2}:)|[Mm]other|[Ff]ather|'
  + '[Mm]om|[Dd]ad|[Ss]pouse|[Ww]ife|[Hh]usband|[Ss]on|[Dd]aughter|[Ss]ister|[Bb]rother|'
  + '[Gg]uardian|[Cc]aregiver|[Pp]artner|[Ss]igned\\sby|[Ee]mergency\\s[Cc]ontact)'
);
// One name word: Capitalised (O'Brien, McDonald, Smith-Jones) or ALL CAPS
// (headers). An apostrophe only as a prefix: "Parkinson's" is not a name word.
const _NAME ="(?:(?:[A-Z]'|Ma?c)?[A-Z][a-z]+(?:-[A-Z]?[a-z]+)?|[A-Z]{2,}(?:['-][A-Z]{2,})?)";
const _INITIAL = '(?:\\s[A-Z]\\.)?';
const _SEP = '\\s{0,2}:?\\s{0,2}';

// Exactly one of the two groups takes part in a match; it ends the match.
const ROLE_NAME_PATTERN = (
  '(?<![A-Za-z])(?:' + _HONORIFIC + '\\s{0,2}(' + _NAME + '(?:' + _INITIAL + '\\s' + _NAME + '){0,2})'
  + '|' + _ROLE + _SEP + '(' + _NAME + _INITIAL + '\\s' + _NAME + '(?:\\s' + _NAME + ')?))'
  + '(?![A-Za-z])'
);

const _DOB_MRN_LABEL = '(?:DOB|D\\.O\\.B\\.|MRN|[Dd]ate\\sof\\s[Bb]irth)(?![A-Za-z])';

// Two branches, one group each: a name heading a line, followed by an ID, a
// date or a DOB/MRN label; or a full name anywhere followed by a DOB/MRN
// label ("for Aisha Vance (Date of birth: ...").
const HEADER_NAME_PATTERN = (
  '(?:^|(?<=\\n))[ \\t]{0,4}(' + _NAME + ',?\\s' + _NAME + ')'
  + '(?=[ \\t]{1,4}(?:[A-Z]{0,3}\\d{5,}|\\d{1,2}/\\d{1,2}/\\d{2,4}|\\d{4}-\\d{2}-\\d{2}|' + _DOB_MRN_LABEL + '))'
  + '|(?<![A-Za-z])(' + _NAME + _INITIAL + '\\s' + _NAME + '(?:\\s' + _NAME + ')?)'
  + '(?=\\s{1,2}\\(?' + _DOB_MRN_LABEL + ')'
);

const _STOP = new Set([
  'ID', 'Id', 'Portal', 'Education', 'Instructions', 'Information', 'Info', 'Name', 'Number',
  'No', 'Care', 'Safety', 'History', 'Record', 'Records', 'Consent', 'Summary', 'Report',
  'Reports', 'Reported', 'States', 'Stated', 'Denies', 'Denied', 'Presents', 'Presented',
  'Tolerated', 'Complains', 'Arrived', 'Admits', 'Admitted', 'Visits', 'Visit', 'Notes',
  'Note', 'Plan', 'Status', 'Satisfaction', 'Experience', 'Advocate', 'Services', 'Account',
  'Address', 'Phone', 'Email', 'Signature', 'Date', 'Medications', 'Allergies', 'Location',
  'Room', 'Bed', 'Unit', 'Type', 'Class', 'Follow', 'Up', 'Lab', 'Labs', 'Results', 'Vitals',
  'Order', 'Orders', 'Discharge', 'Admission', 'Is', 'Was', 'Has', 'Had', 'The', 'And', 'Or',
  'Not', 'To', 'In', 'On', 'At', 'With', 'Of', 'For',
]);

const _NOT_A_SURNAME = new Set([
  'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday',
  'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August',
  'September', 'October', 'November', 'December', 'MD', 'DO', 'RN', 'NP', 'PA',
  'PhD', 'DDS', 'Hospital', 'Clinic', 'Center', 'Medical', 'Health', 'Street', 'Avenue',
  'Road',
  ..._STOP,
]);

/**
 * End of the name in text[start:end], or null if it is not a name. Trailing
 * credentials, weekdays and template words are trimmed ("Dr. Smith MD" ->
 * "Smith"); a template word anywhere else rejects the match.
 */
function trimName(text, start, end) {
  const re = /[A-Za-z]+(?:['-][A-Za-z]+)?/g;
  const slice = text.slice(start, end);
  const words = [];
  let m;
  while ((m = re.exec(slice)) !== null) words.push([m[0], start + m.index + m[0].length]);
  while (words.length && _NOT_A_SURNAME.has(words[words.length - 1][0])) words.pop();
  if (!words.length || words.some(([w]) => _STOP.has(w))) return null;
  return words[words.length - 1][1];
}

/**
 * Surname completion for a ONE-word NER PERSON span: extend over the directly
 * following capitalised word unless it is a weekday, month, credential, place
 * or template word. Never over a possessive ("Parkinson's" is the disease).
 * Returns the (possibly new) end offset.
 */
function extendFirstName(text, start, end) {
  if (text.slice(start, end).trim().includes(' ')) return end;
  const m = /^ ((?:[A-Z]'|Ma?c)?[A-Z][a-z]+(?:-[A-Z]?[a-z]+)?)(?![A-Za-z'])/.exec(text.slice(end));
  if (!m || _NOT_A_SURNAME.has(m[1])) return end;
  return end + m[0].length;
}

const CATEGORY_ALIAS = { ROLE_NAME: 'PERSON', HEADER_NAME: 'PERSON' };
const ROLE_NAME_CATEGORIES = new Set(Object.keys(CATEGORY_ALIAS));

module.exports = {
  ROLE_NAME_PATTERN, HEADER_NAME_PATTERN, CATEGORY_ALIAS, ROLE_NAME_CATEGORIES,
  trimName, extendFirstName,
};
