// Clinical-term veto for NER (v0.13.0, health edition).
//
// Off by default: config.protectClinicalTerms (opt-in, must be === true).
// Mirrors cloakllm-py cloakllm/clinical_terms.py exactly -- the lists and
// patterns are identical (checked from the Python suite).
//
// Drops a NER detection when every word in it is clinical vocabulary, a
// number or a unit (at least one vocabulary word: "INR 97.3", "Hx COPD"), or
// when it is one capitalised word directly followed by a disease word
// ("Crohn's disease", "Cushing syndrome"). Never touches a regex or LLM
// detection, never vetoes a span with any other word in it, and fails closed
// on letters the token pattern does not see. A term missing from the lists
// is over-removal, never a leak.
'use strict';

const ABBREVIATIONS = [
  // history / workflow shorthand
  'Hx', 'Dx', 'Rx', 'Tx', 'Sx', 'Fx', 'PMH', 'PSH', 'FHx', 'SHx', 'HPI', 'ROS', 'NKDA', 'DNR', 'DNI',
  'POLST', 'PRN', 'BID', 'TID', 'QID', 'QD', 'QHS', 'PO', 'IV', 'IM', 'SC', 'SQ', 'OTC', 'ICU', 'ED',
  'PACU', 'PCP', 'EMS', 'EHR', 'EMR',
  // record-field labels (the label, not the value: "DOB 03/09/1985")
  'DOB', 'D.O.B', 'SSN', 'MRN', 'PID', 'CSN', 'FIN', 'NPI', 'DEA', 'MBI', 'HICN',
  // cardiovascular
  'MI', 'STEMI', 'NSTEMI', 'ACS', 'CAD', 'CHF', 'HF', 'HFrEF', 'HFpEF', 'AF', 'AFib', 'A-fib', 'HTN',
  'HLD', 'DVT', 'PE', 'PAD', 'PVD', 'CABG', 'PCI', 'TIA', 'CVA', 'SVT', 'VT', 'VF', 'AAA', 'EKG',
  'ECG', 'TTE', 'TEE', 'LVEF', 'EF', 'BNP', 'NT-proBNP', 'LVH',
  // respiratory
  'COPD', 'OSA', 'ARDS', 'CPAP', 'BiPAP', 'PFT', 'PFTs', 'SOB', 'URI', 'PNA', 'CAP', 'TB',
  'ILD', 'SpO2',
  // GI / liver
  'GERD', 'IBD', 'IBS', 'PUD', 'GI', 'EGD', 'NAFLD', 'NASH', 'MASLD', 'MASH', 'LFT', 'LFTs', 'UC',
  'HCC',
  // renal / urology
  'CKD', 'AKI', 'ESRD', 'ESKD', 'UTI', 'BPH', 'eGFR', 'GFR', 'BUN', 'Cr',
  // endocrine
  'DM', 'T1DM', 'T2DM', 'DM1', 'DM2', 'DKA', 'HHNS', 'TSH', 'T3', 'T4', 'HbA1c', 'A1c', 'A1C',
  'PCOS',
  // neuro / psych
  'MS', 'ALS', 'TBI', 'ADHD', 'OCD', 'PTSD', 'MDD', 'GAD', 'SUD', 'AUD', 'OUD', 'EEG', 'LP',
  // labs / haematology / infection
  'CBC', 'CMP', 'BMP', 'INR', 'PT', 'PTT', 'aPTT', 'Hgb', 'Hb', 'Hct', 'WBC', 'RBC', 'PLT', 'ESR',
  'CRP', 'hsCRP', 'LDL', 'HDL', 'VLDL', 'TG', 'PSA', 'CEA', 'AFP', 'HIV', 'HCV', 'HBV', 'HPV', 'RSV',
  'COVID', 'COVID-19', 'SARS-CoV-2', 'MRSA', 'VRE', 'CDI', 'ABG', 'VBG', 'UA', 'CK', 'LDH', 'ALT',
  'AST', 'ALP', 'GGT', 'INH',
  // imaging
  'CT', 'CTA', 'MRI', 'MRA', 'CXR', 'PET',
  // drug classes
  'ACE', 'ACEi', 'ARB', 'ARNI', 'SGLT2', 'SGLT2i', 'SGLT-2', 'GLP-1', 'GLP-1RA', 'GLP1', 'DPP-4',
  'DPP4', 'NSAID', 'NSAIDs', 'SSRI', 'SSRIs', 'SNRI', 'SNRIs', 'TCA', 'MAOI', 'PPI', 'PPIs', 'DOAC',
  'DOACs', 'NOAC', 'LMWH', 'UFH', 'ASA', 'APAP', 'TNF', 'JAK',
];

const TERMS = [
  'statin', 'statins', 'insulin', 'glargine', 'lispro', 'aspart', 'detemir', 'degludec',
  'apixaban', 'rivaroxaban', 'dabigatran', 'edoxaban', 'warfarin', 'heparin', 'enoxaparin',
  'clopidogrel', 'ticagrelor', 'prasugrel', 'aspirin', 'atorvastatin', 'rosuvastatin',
  'simvastatin', 'pravastatin', 'ezetimibe', 'metformin', 'semaglutide', 'liraglutide',
  'dulaglutide', 'tirzepatide', 'exenatide', 'empagliflozin', 'dapagliflozin', 'canagliflozin',
  'sitagliptin', 'linagliptin', 'glipizide', 'glyburide', 'glimepiride', 'pioglitazone',
  'lisinopril', 'enalapril', 'ramipril', 'benazepril', 'losartan', 'valsartan', 'irbesartan',
  'olmesartan', 'sacubitril', 'amlodipine', 'nifedipine', 'diltiazem', 'verapamil', 'metoprolol',
  'carvedilol', 'atenolol', 'propranolol', 'bisoprolol', 'labetalol', 'hydralazine', 'clonidine',
  'furosemide', 'torsemide', 'bumetanide', 'hydrochlorothiazide', 'chlorthalidone',
  'spironolactone', 'eplerenone', 'digoxin', 'amiodarone', 'sotalol', 'levothyroxine',
  'methimazole', 'prednisone', 'prednisolone', 'methylprednisolone', 'dexamethasone',
  'hydrocortisone', 'omeprazole', 'pantoprazole', 'esomeprazole', 'lansoprazole', 'famotidine',
  'ondansetron', 'metoclopramide', 'sertraline', 'fluoxetine', 'escitalopram', 'citalopram',
  'paroxetine', 'venlafaxine', 'duloxetine', 'bupropion', 'mirtazapine', 'trazodone',
  'quetiapine', 'olanzapine', 'risperidone', 'aripiprazole', 'haloperidol', 'lithium',
  'lamotrigine', 'valproate', 'levetiracetam', 'carbamazepine', 'phenytoin', 'gabapentin',
  'pregabalin', 'tramadol', 'oxycodone', 'hydrocodone', 'morphine', 'fentanyl',
  'buprenorphine', 'methadone', 'naloxone', 'naltrexone', 'acetaminophen', 'paracetamol',
  'ibuprofen', 'naproxen', 'celecoxib', 'amoxicillin', 'azithromycin', 'doxycycline',
  'ciprofloxacin', 'levofloxacin', 'ceftriaxone', 'cephalexin', 'vancomycin', 'metronidazole',
  'nitrofurantoin', 'trimethoprim', 'sulfamethoxazole', 'clindamycin', 'albuterol',
  'tiotropium', 'fluticasone', 'budesonide', 'montelukast', 'allopurinol', 'colchicine',
  'methotrexate', 'adalimumab', 'infliximab', 'hydroxychloroquine', 'tamsulosin', 'finasteride',
  'sildenafil', 'donepezil', 'memantine', 'carbidopa', 'levodopa', 'melatonin', 'zolpidem',
  'lorazepam', 'alprazolam', 'clonazepam', 'diazepam', 'troponin', 'creatinine', 'ferritin',
  'potassium', 'sodium', 'magnesium', 'bilirubin', 'albumin', 'lipase', 'lactate', 'glucose',
  // US public programs: an insurer TYPE, not an identifier
  'medicare', 'medicaid', 'medigap', 'tricare',
];

const UNITS = [
  'mg', 'mcg', 'g', 'kg', 'lb', 'lbs', 'mL', 'ml', 'L', 'dL', 'mg/dL', 'mmol/L', 'mEq/L', 'ng/mL',
  'pg/mL', 'U/L', 'IU', 'units', 'mmHg', 'bpm', '%',
];

// Only nouns that cannot follow a name as a verb or an ordinary noun.
const DISEASE_WORDS = [
  'disease', 'syndrome', 'palsy', 'sarcoma', 'lymphoma', 'thyroiditis', 'disorder', 'phenomenon',
  'ulcer', 'chorea', 'anomaly', 'tumor', 'tumour', 'encephalopathy', 'aneurysm', 'esophagus',
  'contracture', 'ataxia', 'dementia', 'arteritis', 'neuralgia', 'neuroma', 'cyst',
];

// The NER span may or may not include the possessive: spaCy returns
// "Crohn", compromise returns "Addison's".
const EPONYM_WORD_PATTERN = "[A-Z][a-z]+(?:-[A-Z][a-z]+)?(?:'s|s'|')?";
const EPONYM_TAIL_PATTERN = "(?:'s|s'|')?\\s(?:" + DISEASE_WORDS.join('|') + ')(?![A-Za-z])';
const TOKEN_PATTERN = '[A-Za-z0-9]+(?:[./+-][A-Za-z0-9]+)*%?';
const NUMBER_PATTERN = '\\d+(?:[.,]\\d+)?%?';
const CAPS_BEFORE_PATTERN = '(?<![A-Za-z])([A-Z]{2,})[ \\t]+$';
const CAPS_AFTER_PATTERN = '[ \\t]+([A-Z]{2,})(?![A-Za-z])';

const _ABBR = new Set(ABBREVIATIONS);
const _TERMS = new Set(TERMS);
const _UNITS = new Set(UNITS);
const _EPONYM_WORD_RE = new RegExp('^(?:' + EPONYM_WORD_PATTERN + ')$');
const _NUMBER_RE = new RegExp('^(?:' + NUMBER_PATTERN + ')$');
const _CAPS_BEFORE_RE = new RegExp(CAPS_BEFORE_PATTERN);
const _LETTER_RE = /\p{L}/u; // any Unicode letter (Python: [^\W\d_])

function _isTerm(token) {
  return _ABBR.has(token) || _TERMS.has(token.toLowerCase());
}

/**
 * True if the NER detection text[start:end] is clinical vocabulary or the
 * eponym inside a disease name, i.e. should NOT be removed.
 */
function isClinicalSpan(text, start, end) {
  const span = text.slice(start, end);
  if (_EPONYM_WORD_RE.test(span)) {
    const tail = new RegExp(EPONYM_TAIL_PATTERN, 'iy');
    tail.lastIndex = end;
    if (tail.test(text)) return true;
  }
  const tokens = span.match(new RegExp(TOKEN_PATTERN, 'g')) || [];
  if (!tokens.length || !tokens.some(_isTerm)) return false;
  // An all-caps header ("ED SMITH 12345") may give NER only one word of a
  // name. Next to another all-caps word that is not vocabulary, an all-caps
  // span is not vetoed.
  if (span.toUpperCase() === span) {
    const before = _CAPS_BEFORE_RE.exec(text.slice(0, start));
    const after = new RegExp(CAPS_AFTER_PATTERN, 'y');
    after.lastIndex = end;
    const a = after.exec(text);
    if ([before, a].some((m) => m && !_isTerm(m[1]))) return false;
  }
  // Fail closed: a letter the token pattern did not see may be a name.
  if (_LETTER_RE.test(span.replace(new RegExp(TOKEN_PATTERN, 'g'), ''))) return false;
  return tokens.every((t) => _isTerm(t) || _UNITS.has(t) || _NUMBER_RE.test(t));
}

module.exports = {
  ABBREVIATIONS, TERMS, UNITS, DISEASE_WORDS, EPONYM_WORD_PATTERN, EPONYM_TAIL_PATTERN,
  TOKEN_PATTERN, NUMBER_PATTERN, CAPS_BEFORE_PATTERN, CAPS_AFTER_PATTERN, isClinicalSpan,
};
