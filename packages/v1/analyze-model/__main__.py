#--kind python:default
#--web true
# Note: this timeout is 10 minutes - the max allowed - so models can
# respond when they are free without being cut off.
#--timeout 600000
import types, os, analyze_model

builder = []
## build-context ##
#--param AI_BASE_URL "$AI_BASE_URL"
def init_ai_base_url(args, ctx):
  value = args.get("AI_BASE_URL") or os.getenv("AI_BASE_URL")
  setattr(ctx, "AI_BASE_URL", value)
builder.append(init_ai_base_url)
#--param AI_API_KEY "$AI_API_KEY"
def init_ai_api_key(args, ctx):
  value = args.get("AI_API_KEY") or os.getenv("AI_API_KEY")
  setattr(ctx, "AI_API_KEY", value)
builder.append(init_ai_api_key)

def main(args):
  try:
    ctx = types.SimpleNamespace()
    for fn in builder: fn(args, ctx)
    return { "body": analyze_model.main(args, ctx=ctx) }
  except Exception as e:
    import traceback
    traceback.print_exc()
    return {
      "body": {"error": str(e) },
      "statusCode": 500
    }
