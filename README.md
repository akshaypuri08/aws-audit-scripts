# AWS NACL Review Tool

## Overview
This tool reviews AWS Network ACLs for a given account and provides logging output with basic recommendations.

## Usage

```bash
python main.py <aws-profile-name>
```

## Logs
Output will be stored in:
```
logs/nacl_review.log
```

## Structure

- `main.py` - Entry point
- `modules/nacl_review.py` - NACL logic
- `utils/aws_session.py` - Session and identity