# Business-Friendly Remediation Guide

This guide translates technical findings into plain-language actions for business stakeholders.

## For Executives

| Risk | Simple Explanation | Action Required |
|------|--------------------|-----------------|
| Broken Authentication | Anyone can access the API without a password | Approve budget for an authentication system |
| Data Exposure | Customer data may be visible to attackers | Approve encryption and data-minimization work |
| Rate Limiting | Attackers can overload servers or automate requests | Approve API gateway/rate-control implementation |
| Missing Headers | Browser-facing protections may be weakened | Engineering team should add appropriate headers |

## For Developers

### 1. Authentication Fix

```python
from functools import wraps
from flask import request, jsonify
import jwt

SECRET_KEY = "replace-with-a-secure-secret"

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token or not token.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        try:
            jwt.decode(
                token.split()[1],
                SECRET_KEY,
                algorithms=["HS256"],
            )
        except jwt.PyJWTError:
            return jsonify({"error": "Invalid token"}), 403
        return f(*args, **kwargs)
    return decorated
```

### 2. Rate Limiting Fix

```python
from flask_limiter import Limiter

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per minute"],
)
```

### 3. Security Headers Fix

```python
@app.after_request
def add_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response
```

### 4. Data Masking Fix

```python
def mask_sensitive(data):
    data = dict(data)
    for key in ["password", "token", "ssn"]:
        if key in data:
            data[key] = "***REDACTED***"
    return data
```

### 5. Input Validation Fix

```python
from marshmallow import Schema, fields, validate

class InputSchema(Schema):
    input = fields.Str(
        validate=validate.Regexp(r"^[a-zA-Z0-9 ]+$")
    )
```
