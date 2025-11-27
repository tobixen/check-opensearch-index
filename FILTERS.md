# Advanced Filter Examples for OpenSearch

## Range Queries (e.g., HTTP status 500-600)

```bash
# HTTP status between 500 and 599
./check_opensearch_index.py -i logs-* -w 300 -c 600 \
  --filter '{"range": {"http_status": {"gte": 500, "lt": 600}}}'

# HTTP status >= 500
./check_opensearch_index.py -i logs-* -w 300 -c 600 \
  --filter '{"range": {"http_status": {"gte": 500}}}'

# Age field less than 30
./check_opensearch_index.py -i logs-* -w 300 -c 600 \
  --filter '{"range": {"age": {"lt": 30}}}'
```

## Exists Queries (check if field is defined)

```bash
# Documents where 'error_code' field exists
./check_opensearch_index.py -i logs-* -w 300 -c 600 \
  --filter '{"exists": {"field": "error_code"}}'

# Documents where 'user_id' field exists
./check_opensearch_index.py -i logs-* -w 300 -c 600 \
  --filter '{"exists": {"field": "user_id"}}'
```

## Missing Fields (field is NOT defined)

```bash
# Documents missing 'response_time' field
./check_opensearch_index.py -i logs-* -w 300 -c 600 \
  --filter '{"bool": {"must_not": {"exists": {"field": "response_time"}}}}'
```

## Multiple Conditions (AND/OR/NOT)

```bash
# HTTP 5xx errors AND slow response (multiple filters in array = AND)
./check_opensearch_index.py -i logs-* -w 300 -c 600 \
  --filter '[{"range": {"http_status": {"gte": 500}}}, {"range": {"response_time": {"gte": 1000}}}]'

# Complex bool query: (status >= 500 OR status == 404) AND error_message exists
./check_opensearch_index.py -i logs-* -w 300 -c 600 \
  --filter '{
    "bool": {
      "must": [
        {"exists": {"field": "error_message"}}
      ],
      "should": [
        {"range": {"http_status": {"gte": 500}}},
        {"term": {"http_status": 404}}
      ],
      "minimum_should_match": 1
    }
  }'
```

## Wildcard and Regex

```bash
# Message contains "error" or "fatal" (case insensitive)
./check_opensearch_index.py -i logs-* -w 300 -c 600 \
  --filter '{"query_string": {"query": "message:(*error* OR *fatal*)", "default_operator": "AND"}}'

# Wildcard on keyword field
./check_opensearch_index.py -i logs-* -w 300 -c 600 \
  --filter '{"wildcard": {"service.keyword": "backend-*"}}'

# Regex match
./check_opensearch_index.py -i logs-* -w 300 -c 600 \
  --filter '{"regexp": {"message.keyword": ".*[Ee]rror.*"}}'
```

## Nested Queries

```bash
# For nested objects
./check_opensearch_index.py -i logs-* -w 300 -c 600 \
  --filter '{
    "nested": {
      "path": "user",
      "query": {
        "term": {"user.status": "active"}
      }
    }
  }'
```

## Practical Reverse Mode Examples

```bash
# Alert if 5xx errors found in last 5 minutes
./check_opensearch_index.py -i nginx-* --reverse --min-critical 300 -k \
  --filter '{"range": {"http_status": {"gte": 500, "lt": 600}}}'

# Alert if documents with error_code field appear
./check_opensearch_index.py -i app-logs-* --reverse --min-warning 600 -k \
  --filter '{"exists": {"field": "error_code"}}'

# Alert if slow queries found (response_time > 5000ms AND error exists)
./check_opensearch_index.py -i db-logs-* --reverse --min-critical 300 -k \
  --filter '[{"range": {"response_time": {"gte": 5000}}}, {"exists": {"field": "error"}}]'
```
