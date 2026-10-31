import os
from dotenv import load_dotenv
from openai import OpenAI
from uagents import Agent, Context, Protocol
from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement,
    ChatMessage,
    EndSessionContent,
    TextContent,
    chat_protocol_spec,
)

load_dotenv()

# Get your ASI:One API key from https://asi1.ai/dashboard/api-keys
asi1_api_key = os.getenv("ASI1_API_KEY")
if not asi1_api_key:
    raise RuntimeError(
        "ASI1_API_KEY is not set. Add it to your environment or .env file."
    )

# Initialize OpenAI client pointing to the ASI:One endpoint
client = OpenAI(
    base_url="https://api.asi1.ai/v1",
    api_key=asi1_api_key,
)

# Initialize the uAgent with Mailbox enabled for Agentverse connection
agent = Agent(
    name="CodeReviewPipelineAgent",
    seed="your_unique_secure_pipeline_seed_here",
    port=8001,
    mailbox=True,
    publish_agent_details=True,
)

# Load the Chat Protocol expected by ASI:One
protocol = Protocol(spec=chat_protocol_spec)

@protocol.on_message(ChatMessage)
async def handle_message(ctx: Context, sender: str, msg: ChatMessage):
    # Acknowledge incoming message immediately
    await ctx.send(
        sender, ChatAcknowledgement(acknowledged_msg_id=msg.msg_id)
    )

    # Extract user code snippet or repository query from chat content
    code_input = ""
    for item in msg.content:
        if isinstance(item, TextContent):
            code_input += item.text

    ctx.logger.info("Received code snippet for review pipeline. Processing...")

    # Multi-Agent Pipeline Execution via ASI:One LLM
    pipeline_prompt = (
        "You are an automated Multi-Agent Code Review and Security Pipeline consisting of 3 agents:\n"
        "1. Ingestion & Parsing Agent: Extracts context, language, and structural changes.\n"
        "2. Security & Vulnerability Scanner Agent: Scans for bugs, OWASP Top 10 risks, and security flaws.\n"
        "3. Summary & Recommendation Agent: Synthesizes findings into a clear, actionable review report with fixes.\n\n"
        f"Analyze the following code/request through this 3-stage pipeline and provide the final structured report:\n\n{code_input}"
    )

    response_text = "Pipeline execution failed."
    try:
        r = client.chat.completions.create(
            model="asi1",
            messages=[
                {
                    "role": "system",
                    "content": "You are a rigorous code review and security analysis pipeline. Be concise, technical, and structured.",
                },
                {"role": "user", "content": pipeline_prompt},
            ],
            max_tokens=2048,
        )
        response_text = str(r.choices[0].message.content)
    except Exception as err:
        ctx.logger.exception("Error executing pipeline with ASI:One: %s", err)

    # Send back the review report wrapped in the Chat Protocol
    await ctx.send(
        sender,
        ChatMessage(
            content=[
                TextContent(type="text", text=response_text),
                EndSessionContent(type="end-session"),
            ]
        ),
    )

@protocol.on_message(ChatAcknowledgement)
async def handle_ack(ctx: Context, sender: str, msg: ChatAcknowledgement):
    pass

# Include protocol and publish manifest for Agentverse discovery
agent.include(protocol, publish_manifest=True)

if __name__ == "__main__":
    agent.run()