import { parseIntrospectionResponse, generateGraphQLExploits } from '../server/services/aev/graphql-exploit-strategy';

async function main() {
  const res = await fetch('https://brokencrystals.com/graphql', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      query: '{ __schema { types { name fields { name args { name type { name kind ofType { name } } } type { name kind ofType { name } } } } queryType { name } mutationType { name } } }'
    }),
  });
  const body = await res.text();
  console.log('Response status:', res.status);
  console.log('Body preview:', body.slice(0, 300));

  const schema = parseIntrospectionResponse(body);
  if (schema) {
    console.log('\nQuery fields:');
    for (const f of schema.queryFields) {
      console.log(`  ${f.name}(${f.args.map(a => `${a.name}: ${a.type}`).join(', ')}) → ${f.typeName}`);
    }
    console.log('\nMutation fields:');
    for (const f of schema.mutationFields) {
      console.log(`  ${f.name}(${f.args.map(a => `${a.name}: ${a.type}`).join(', ')}) → ${f.typeName}`);
    }
    console.log('\nHas auth:', schema.hasAuth);
    console.log('Has user data:', schema.hasUserData);
    const payloads = generateGraphQLExploits(schema);
    console.log('\nGenerated payloads:', payloads.length);
    for (const p of payloads.slice(0, 5)) {
      console.log(`  [${p.vulnClass}] ${p.name}`);
      console.log(`    ${p.query.slice(0, 100)}`);
    }
  } else {
    console.log('Schema parse failed');
    console.log('Full body:', body.slice(0, 1000));
  }
}

main().catch(console.error);
