# Documentation style

Use [ASD-STE100 Simplified Technical English](https://www.asd-ste100.org/about_STE.html) as the style reference for Leelo documentation and comments.
Issue 9 is the current reference for this rewrite.
These edits apply the style rules. They do not establish full compliance with the standard and dictionary.

## Write clear text

* Use short sentences. Limit instructions to 20 words and descriptions to 25 words.
* Give one instruction in each sentence.
* Use the active voice and simple verb forms.
* Put a condition before the instruction that depends on that condition.
* Give each paragraph one subject. Use a maximum of six sentences in a paragraph.
* Use the same term for the same item throughout the project.
* Include necessary articles and explicit subjects. Do not shorten words with contractions.
* Use technical terms when a simpler word would change the meaning.

These rules summarize the style guidance. Refer to the standard for the full rules and dictionary.

## Preserve technical meaning

Keep commands, identifiers, code examples, formulas, constants, units, and links accurate.
Keep the distinction between implemented functions, design requirements, test results, and proved properties.
Do not remove a required condition to shorten a sentence.
Do not change `must` to `can` or `should` in a requirement.

Keep these terms distinct:

| Term | Meaning in this project |
|---|---|
| Credential | Secret input that permits access through a LUKS keyslot. |
| Volume key | The key that encrypts the volume data. |
| Evaluation key | The evaluator's private VOPRF key. |
| Signing key | The private key that signs an envelope. |
| Trust key | The external public key that verifies an envelope signature. |
| Keyslot | LUKS metadata that protects access to the volume key. |
| Token | The LUKS2 metadata object that stores the Leelo envelope and slot association. |
| Envelope | The signed Leelo data structure with policy and protected recovery material. |
| Proof obligation | A condition that the verifier checks. It is not necessarily an independent security theorem. |

Preserve license text, standard identifiers, quoted tool output, and historical test records.
After a comment change, rerun the applicable proof before you record a new source hash.
