console.log('Starting demo...');

try {
  console.log('About to import...');
  const module = await import('./dist/src/interfaces/http-client.js');
  console.log('Import successful:', Object.keys(module));
} catch (error) {
  console.error('Import failed:', error);
}

console.log('Demo complete.');
