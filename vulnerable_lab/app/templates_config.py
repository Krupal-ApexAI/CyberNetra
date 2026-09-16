"""
Jinja2Templates configuration with backward and forward compatibility
for Starlette 0.28+ and 0.35+ TemplateResponse signatures.
"""
import os
from typing import Any
from starlette.templating import Jinja2Templates as StarletteJinja2Templates
from starlette.responses import Response

TEMPLATES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "templates"))

class CompatibleJinja2Templates(StarletteJinja2Templates):
    """
    Subclass that flexibly handles both:
      TemplateResponse(request, name, context, ...)
      and legacy TemplateResponse(name, context, ...)
    """
    def TemplateResponse(self, *args, **kwargs) -> Response:
        if args and isinstance(args[0], str):
            name = args[0]
            context = args[1] if len(args) > 1 else kwargs.pop("context", {})
            request = kwargs.pop("request", None)
            if request is None and isinstance(context, dict):
                request = context.get("request")
            return super().TemplateResponse(request=request, name=name, context=context, **kwargs)
        return super().TemplateResponse(*args, **kwargs)

templates = CompatibleJinja2Templates(directory=TEMPLATES_DIR)
