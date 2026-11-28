# Minimal shim: the upstream app imports make_lambda_handler for AWS Lambda.
# In the demo we run it as a normal Flask server, so this is a no-op wrapper.
def make_lambda_handler(app):
    def handler(event, context):  # pragma: no cover - not used in the container
        raise RuntimeError("Lambda handler is not used in the demo container")
    return handler
