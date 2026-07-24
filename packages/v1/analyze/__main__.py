#--kind python:default
#--web true
# Note: this timeout is 5 minutes - 10 minutes is max allowed
#--timeout 300000
import types, os, analyze

builder = []
## build-context ##
#--param OLLAMA_API_KEY "$OLLAMA_API_KEY"
def init_ollama_api_key(args, ctx):
  value = args.get("OLLAMA_API_KEY") or os.getenv("OLLAMA_API_KEY")
  if not value:
    raise RuntimeError("Required secret OLLAMA_API_KEY is not configured")
  setattr(ctx, "OLLAMA_API_KEY", value)
builder.append(init_ollama_api_key)
#--param OLLAMA_HOST "$OLLAMA_HOST"
def init_ollama_host(args, ctx):
  value = args.get("OLLAMA_HOST") or os.getenv("OLLAMA_HOST")
  if not value:
    raise RuntimeError("Required secret OLLAMA_HOST is not configured")
  setattr(ctx, "OLLAMA_HOST", value)
builder.append(init_ollama_host)

def main(args):
  try:
    ctx = types.SimpleNamespace()
    for fn in builder: fn(args, ctx)
    return { "body": analyze.main(args, ctx=ctx) }
  except Exception as e:
    import traceback
    traceback.print_exc()
    return {
      "body": {"error": str(e) },
      "statusCode": 500
    }
