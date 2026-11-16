// Synthetic sample for the CLI tests: decodes a base64 string and evals it.
// The payload is console.log("hello"); the tests never run this file.
const payload = Buffer.from('Y29uc29sZS5sb2coImhlbGxvIik=', 'base64').toString();
eval(payload);
