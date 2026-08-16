#--kind python:default
#--web true
# Note: this timeout is 10 minutes - the max allowed - so models can
# respond when they are free without being cut off.
#--timeout 600000
import types, os, analyze_model

builder = []
## build-context ##
#--param AI_API_HOST "$AI_API_HOST"
def init_ai_api_host(args, ctx):
  value = args.get("AI_API_HOST") or os.getenv("AI_API_HOST")
  if not value:
    raise RuntimeError("Required secret AI_API_HOST is not configured")
  setattr(ctx, "AI_API_HOST", value)
builder.append(init_ai_api_host)
#--param AI_API_KEY "$AI_API_KEY"
def init_ai_api_key(args, ctx):
  value = args.get("AI_API_KEY") or os.getenv("AI_API_KEY")
  if not value:
    raise RuntimeError("Required secret AI_API_KEY is not configured")
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
