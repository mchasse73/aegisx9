// Builds planted sensitive values at runtime so no credential-shaped literal is stored.
const pick = (alphabet, n) =>
  Array.from({ length: n }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join("");
const UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const AN = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

module.exports = {
  cloudKey: () => ["AK", "IA"].join("") + pick(UP, 16),
  repoToken: () => ["gh", "p_"].join("") + pick(AN, 36),
  email: () => ["test.person", "example.org"].join("@"),
};
