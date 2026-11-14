// Master password strength and passphrase suggestions.

import { randomIndex } from './generator';
import { words } from './wordlist';

export type Strength = { score: 0 | 1 | 2 | 3 | 4; warning: string; suggestions: string[] };

// The minimum zxcvbn score for a master password ("safely unguessable").
export const minScore = 3;

// zxcvbn and its dictionaries are large, so they load the first time a
// password is checked rather than at startup.
let checker: Promise<(password: string, inputs: string[]) => Strength> | undefined;

function loadChecker() {
  checker ??= Promise.all([import('@zxcvbn-ts/core'), import('@zxcvbn-ts/language-common'), import('@zxcvbn-ts/language-en')]).then(([core, common, en]) => {
    const factory = new core.ZxcvbnFactory({ dictionary: { ...common.dictionary, ...en.dictionary }, graphs: common.adjacencyGraphs, translations: en.translations });
    return (password: string, inputs: string[]) => {
      const result = factory.check(password, inputs);
      return { score: result.score, warning: result.feedback.warning || '', suggestions: result.feedback.suggestions };
    };
  });
  return checker;
}

// checkStrength rates a password, penalising words such as the GitHub login.
export async function checkStrength(password: string, inputs: string[] = []): Promise<Strength> {
  if (!password) return { score: 0, warning: '', suggestions: [] };
  return (await loadChecker())(password, inputs);
}

// suggestPassphrase picks words uniformly from the EFF list: 6 words give
// about 77 bits, beyond any offline attack on Argon2id.
export function suggestPassphrase(count = 6): string {
  return Array.from({ length: count }, () => words[randomIndex(words.length)]).join('-');
}

export const strengthLabels = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'] as const;
