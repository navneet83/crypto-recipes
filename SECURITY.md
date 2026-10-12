# Security

The code here is reference material, not a packaged dependency, so there are no releases to patch. If you find a problem, open an issue unless it is something readers who already copied a file need to hear about privately first. In that case email the address on the GitHub profile of the repository owner.

Things that count as a security problem in this repository:

- An implementation that accepts an input from `negative.json`, or any tampered, truncated or wrong-key input, and returns plaintext.
- An implementation that diverges from the recipe page in a way the vectors do not catch (for example, a parameter that is lower than the page says).
- A recipe page that recommends something the current guidance from the platform vendors or the IETF has moved away from.

Things that are not: feature requests for new recipes or languages, and performance.
