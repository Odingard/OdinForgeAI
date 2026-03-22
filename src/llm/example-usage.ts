import { LlmRouter } from "./router";

async function main() {
  const router = new LlmRouter();

  const endpointTyping = await router.endpointTyper([
    {
      role: "system",
      content:
        "Classify the endpoint for OdinForge. Return a concise answer with type, trust zone, sensitivity, and chain role.",
    },
    {
      role: "user",
      content: [
        "URL: https://target.example/api/auth/login",
        "Method: POST",
        "Content-Type: application/json",
      ].join("\n"),
    },
  ]);

  console.log("Endpoint typing result:");
  console.log(endpointTyping);

  const plan = await router.planner([
    {
      role: "system",
      content:
        "You are the OdinForge planner. Choose the next bounded exploit action. Never invent evidence.",
    },
    {
      role: "user",
      content: [
        "Surface model:",
        "- /graphql is a pivot",
        "- /admin is a target",
        "- session cookie harvested",
        "- replay available",
        "",
        "What should be tried next?",
      ].join("\n"),
    },
  ]);

  console.log("Planner result:");
  console.log(plan);

  const reasoning = await router.reasoningStream([
    {
      role: "system",
      content:
        "Produce one concise operator-facing reasoning line. Deterministic, no fluff, no speculation.",
    },
    {
      role: "user",
      content:
        "GraphQL endpoint classified as pivot. Session cookie harvested. Prioritizing replay against privileged surfaces.",
    },
  ]);

  console.log("Reasoning stream result:");
  console.log(reasoning);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
